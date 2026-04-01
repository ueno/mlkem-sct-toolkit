import os
import sys
import getopt
import ecdsa.der as der
import random
from threading import Thread, Event
from kyber_py.ml_kem.pkcs import ek_from_pem
from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.progress_report import progress_report


if sys.version_info < (3, 8):
    print("This script is compatible with Python 3.8 and later only")
    sys.exit(1)


class CiphertextGenerator(object):
    """
    Class for generating different kinds of ML-KEM ciphertexts.
    """

    types = {}

    def __init__(self, kem, public_key):
        self.kem = kem
        self.key = public_key

    types["valid"] = 1

    def valid(self, gen_id):
        """
        Creates a valid ML-KEM ciphertext.

        gen_id is just to have ability to have duplicate generators
        """
        _, encaps = self.kem.encaps(self.key)
        return encaps

    types["random"] = 1

    def random(self, gen_id):
        """
        Creates a completely random ML-KEM ciphertext.

        Returns amount of random bytes consistent with the set KEM.

        gen_id is just to have the ability to have duplicate generators
        """
        cipher_bytes = 32 * (self.kem.du * self.kem.k + self.kem.dv)
        return random.randbytes(cipher_bytes)

    types["xor_u_coefficient"] = 2

    def xor_u_coefficient(self, pos, val):
        """
        Creates a ML-KEM ciphertext with a modified u coefficient

        Modifies the "u" part of the ciphertext by xor-ing the
        coefficient at position pos in the ciphertext.

        pos is the position of the coefficient. "0" for first one,
        "-1" for the last one. There are k*256 coefficients.

        val is the value to xor with, must be between 1 and 2**du exclusive
        """
        assert val > 0
        assert val < 2 ** self.kem.du
        if pos < 0:
            pos %= self.kem.k * 256
        _, encaps = self.kem.encaps(self.key)

        n = self.kem.k * self.kem.du * 32
        c1, c2 = encaps[:n], encaps[n:]

        u = self.kem.M.decode_vector(c1, self.kem.k, self.kem.du)
        assert len(u._data[0]) == self.kem.k
        u._data[0][pos//256].coeffs[pos%256] ^= val
        cx = u.encode(self.kem.du)
        return cx + c2

    types["xor_v_coefficient"] = 2

    def xor_v_coefficient(self, pos, val):
        """
        Create a ML-KEM ciphertext with a modified v coefficient

        Modifies the "v" part of the ciphertext by xor-ing the
        coefficient at position pos in the ciphertext.

        pos is the postition of the coefficient. "0" for the first one,
        "-1" or "255" for the last one.

        val is the value to xor with, must be between 1 and 2**dv exclusive
        """
        assert val > 0
        assert val < 2 ** self.kem.dv

        _, encaps = self.kem.encaps(self.key)

        n = self.kem.k * self.kem.du * 32
        c1, c2 = encaps[:n], encaps[n:]

        v = self.kem.R.decode(c2, self.kem.dv)
        v.coeffs[pos] ^= val

        cx = v.encode(self.kem.dv)

        return c1 + cx

    types["one_u_remain"] = 1

    def one_u_remain(self, pos):
        """
        Create a ML-KEM ciphertext with only one non-zero u polynomial

        pos the number of the polynomial to retain, between 0 and k-1 inclusive
        """
        assert pos >= 0
        assert pos < self.kem.k

        u = bytearray(self.kem.k * self.kem.du * 32)
        u[pos * self.kem.du * 32:(pos+1) * self.kem.du * 32] = \
            random.randbytes(self.kem.du * 32)

        v = random.randbytes(self.kem.dv * 32)

        return bytes(u + v)

    types["one_v_remain"] = 1

    def one_v_remain(self, pos):
        """
        Create a ML-KEM ciphertext with only one non-zero v coefficient

        pos the position of the coefficient to retain, between 0 and 255
        inclusive
        """
        assert pos >= -256
        assert pos <= 255

        u = random.randbytes(self.kem.k * self.kem.du * 32)

        v = self.kem.R.decode(bytes(self.kem.dv * 32), self.kem.dv)
        v.coeffs[pos] = random.randint(0, 2 ** self.kem.dv - 1)

        cx = v.encode(self.kem.dv)

        return u + cx


def help_msg():
    print(
"""
{0} -c key.pem [-o dir] ciphertext_name[="param1 param2"] [ciphertext_name]

Generate ciphertexts for testing ML-KEM decapsulation interface against
timing side-channel.

-c key.pem       Path to PEM-encoded ML-KEM encapsulation key.
-o dir           Directory that will contain the generated ciphertexts.
                 "ciphertexts" by default.
--describe=name  Describe the specified probe
--repeat=num     Save the ciphertexts in random order in a single file
                 (ciphers.bin) in the specified directory together with a
                 file specifying the order (log.csv). Used for generating
                 input file for timing tests.
--force          Don't abort when the output dir exists
--status-delay num How often to print the status line.
--status-newline Use newline instead of carriage return for
                 printing status line. Useful when redirecting
                 standard output to a file.
--verbose        Print status progress when generating repeated probes
--help           This message

Supported probes:
{1}
""".format(sys.argv[0], "\n".join("{0}, args: {1}".format(
    i, j) for i, j in CiphertextGenerator.types.items())))


def gen_timing_probes(out_dir, pub, kem, args, repeat, verbose=False,
                      status_delay=None, status_newline=None):
    generator = CiphertextGenerator(kem, pub)

    probes = {}
    probe_names = []

    # parse the parameters
    for arg in args:
        ret = arg.split('=')
        if len(ret) == 1:
            name = ret[0]
            params = []
        elif len(ret) == 2:
            name, params = ret
            ret = params.split(' ')
            params = [int(i, 16) if i[:2] == '0x' else int(i) for i in ret]
        else:
            print("ERROR: Incorrect formatting of option: {0}".format(arg))

        if len(params) != generator.types[name]:
            print("ERROR: Incorrect number of parameters specified for probe "
                  "{0}, expected: {1}, got {2}".format(
                      name, generator.types[name], len(params)),
                  file=sys.stderr)
            sys.exit(1)


        method = getattr(generator, name)

        probe_name = "_".join([name] + [str(i) for i in params])

        if probe_name in probes:
            print("ERROR: duplicate probe name and/or parameters: {0}, {1}"
                  .format(name, params))
            sys.exit(1)

        probes[probe_name] = (method, params)
        probe_names.append(probe_name)

    # create an order in which we will write the ciphertexts in
    log = Log(os.path.join(out_dir, "log.csv"))

    log.start_log(probes.keys())

    for _ in range(repeat):
        log.shuffle_new_run()

    log.write()

    # reset the log position
    log.read_log()

    try:
        # start progress reporting
        status = [0, len(probe_names) * repeat, Event()]
        if verbose:
            kwargs = {}
            kwargs['unit'] = ' ciphertext'
            kwargs['prefix'] = 'decimal'
            kwargs['delay'] = status_delay
            kwargs['end'] = status_newline
            progress = Thread(target=progress_report, args=(status,),
                              kwargs=kwargs)
            progress.start()

        with open(os.path.join(out_dir, "ciphers.bin"), "wb") as out:
            # start the ciphertext generation
            for executed, index in enumerate(log.iterate_log()):
                status[0] = executed

                p_name = probe_names[index]
                p_method, p_params = probes[p_name]

                ciphertext = p_method(*p_params)

                out.write(ciphertext)
    finally:
        if verbose:
            status[2].set()
            progress.join()
            print()

    print("done")



if __name__ == "__main__":
    key = None
    kem = None
    out_dir = "ciphertexts"
    repeat = None
    force_dir = False
    verbose = False
    status_delay = None
    status_newline = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "c:o:", ["help", "describe=", "repeat=",
                                              "force", "verbose",
                                              "status-delay=",
                                              "status-newline"])
    for opt, arg in opts:
        if opt == "-c":
            with open(arg, "r") as key_fd:
                kem, key = ek_from_pem(key_fd.read())
        elif opt == "-o":
            out_dir = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--force":
            force_dir = True
        elif opt == "--repeat":
            repeat = int(arg)
        elif opt == "--status-delay":
            status_delay = float(arg)
        elif opt == "--status-newline":
            status_newline = '\n'
        elif opt == "--verbose":
            verbose = True
        elif opt == "--describe":
            try:
                fun = getattr(CiphertextGenerator, arg)
            except Exception:
                help_msg()
                raise ValueError("No ciphertext named {0}".format(arg))
            print("{0}:".format(arg))
            print(fun.__doc__)
            sys.exit(0)
        else:
            raise ValueError("Unrecognised option: {0}".format(opt))

    if not args:
        print("ERROR: No ciphertexts specified", file=sys.stderr)
        sys.exit(1)

    if not key:
        print("ERROR: No encapsulation key specified", file=sys.stderr)
        sys.exit(1)

    if repeat is not None and repeat <= 0:
        print("ERROR: repeat must be a positive integer", file=sys.stder)
        sys.exit(1)

    print("Will save ciphertexts to {0}".format(out_dir))

    try:
        os.mkdir(out_dir)
    except FileExistsError:
        if force_dir:
            pass
        else:
            raise

    if repeat is None:
        single_shot(out_dir, key, kem, args)
    else:
        gen_timing_probes(out_dir, key, kem, args, repeat, verbose,
                          status_delay, status_newline)

    print("done")
