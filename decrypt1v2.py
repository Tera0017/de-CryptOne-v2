"""
Author: @Tera0017
"""
import json
from modules.decryptexecutable import DecryptExecutable64, DecryptExecutable86
from modules.generic import message, writefile, get_osa, gen_name, process_args, get_size, ERRORS


class DeCrypt12:
    def __init__(self, filepath):
        self.filepath = filepath

    def print_decr_pckg(self, decr_pckg):
        decr_pckg['Resource']['data'] = decr_pckg['Resource']['data'].hex()
        for k1 in decr_pckg:
            for k2 in decr_pckg[k1]:
                if type(decr_pckg[k1][k2]) is int:
                    decr_pckg[k1][k2] = hex(decr_pckg[k1][k2])
        json_file = gen_name(self.filepath, 'CryptOne_JSON_').split('.')[0] + '.json'
        writefile(json_file, json.dumps(decr_pckg), 'w')
        message('CryptOne Decryption package successfully dumped: {}'.format(json_file))

    def unpack(self, flag=False):
        line = '------------------------'
        osa = get_osa(file_path=self.filepath)

        message(line)
        message('CryptOne Unpacker {}'.format(hex(osa)))
        message(line)

        if osa == 0x64:
            message(ERRORS['04'])
            return False

        DecryptExec = {
            0x32: DecryptExecutable86,
            0x64: DecryptExecutable64,
        }[osa]

        executable = DecryptExec(self.filepath)
        executable_data, decr_pckg = executable.decrypt()
        filename_executable = gen_name(self.filepath, 'CryptOne_Exec_')
        writefile(filename_executable, executable_data)
        message('CryptOne Executable Size: {}'.format(hex(get_size(executable_data)).upper()))
        message('CryptOne Executable successfully dumped: {}'.format(filename_executable))
        if flag:
            message(line)
            self.print_decr_pckg(decr_pckg)
        message(line)
        return True


if __name__ == '__main__':
    decrypt1 = DeCrypt12(process_args())
    decrypt1.unpack()
