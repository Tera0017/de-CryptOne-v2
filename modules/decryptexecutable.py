"""
Author: @Tera0017
"""
import struct
import pefile
from .generic import match_rule, readfile, split_per, message, fix_dword, get_size, ERRORS


class DecryptExecutable:
    def __init__(self, filepath, osa, rules):
        self.filepath = filepath
        self.filedata = readfile(filepath)
        self.pe = pefile.PE(filepath)
        self.rules = rules
        self.osa = osa

    def get_resources(self):
        resources = []
        for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for entry in rsrc.directory.entries:
                resource = {}
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = self.pe.get_memory_mapped_image()[offset:offset + size]
                try:
                    if size < 0x3000 or len(data) == 0:
                        raise IndexError
                except IndexError:
                    continue
                resource["name"] = str(entry.name)
                resource["offset"] = entry.directory.entries[0].data.struct.OffsetToData
                resource["size"] = entry.directory.entries[0].data.struct.Size
                resource["data"] = data
                resources.append(resource)

        if len(resources) == 1:
            return resources
        elif len(resources) > 1:
            return sorted(resources, key=lambda i: i['size'], reverse=True)

        raise ValueError(ERRORS['05'])

    def get_func_data(self, idx):
        try:
            s = b'\x55\x8B\xEC'
            e = b'\x8B\xE5\x5D\xC3'
            ss = self.filedata[idx-1000:idx].rindex(s) + idx - 1000
            ee = self.filedata[ss:].index(e) + ss
            return self.filedata[ss:ee]
        except ValueError:
            return self.filedata[idx - 100: idx + 600]

    def get_matches(self, zrules, data=None):
        for rule in zrules:
            matches = match_rule(self.rules[rule], self.filedata if data is None else data)
            if matches:
                return matches, rule
        return []

    def offset_vars(self, data, vars):
        matches, rule = self.get_matches([k for k in self.rules.keys() if '$codev2' in k], data)
        opr1 = b'\xC7\x05'
        for match in matches:
            opcodes = match[2]
            chunk_offset = opcodes[2: 2 + 4]
            z = opr1 + chunk_offset
            idx = data.index(z) + len(z)
            vars['chunk_size'] = struct.unpack('I', data[idx: idx + 4])[0]
            junk_offset = opcodes[-11: -11 + 4]
            z = opr1 + junk_offset
            if z in data:
                idx = data.index(z) + len(z)
                vars['junk_size'] = struct.unpack('I', data[idx: idx + 4])[0]
            else:
                vars['junk_size'] = 0x0
            data2 = data[match[0] + len(match[2]) + 1:]
            break
        matches, rule = self.get_matches([k for k in self.rules.keys() if '$codev3' in k], data2)
        for match in matches:
            opcodes = match[2]
            xor_add_key_offset = opcodes[2: 2 + 4]
            z = opr1 + xor_add_key_offset
            idx = data.index(z) + len(z)
            vars['xor_add_key'] = struct.unpack('I', data[idx: idx + 4])[0]
            if rule == '$codev31':
                xor_key_offset = opcodes[8: 8 + 4]
                z = opr1 + xor_key_offset
                idx = data.index(z) + len(z)
                vars['xor_key'] = struct.unpack('I', data[idx: idx + 4])[0]
                vars['minus_xor'] = -1 * struct.unpack('I', opcodes[-5: -5 + 4])[0]
                vars['xor_add_key'] += vars['minus_xor']
            else:
                vars['xor_key'] = struct.unpack('I', opcodes[-5: -5 + 4])[0]
        return vars

    def get_vars2(self):
        def clean_data(data):
            rule = '{6A ?? E8 ?? ?? ?? ??}'
            for match in match_rule(rule, data):
                data = data.replace(match[2], b'')
            return data

        vars = {
            'loop_count': 0x0, 'chunk_size': 0x0, 'junk_size': 0x0,
            'xor_key': 0x0, 'xor_add_key': 0x0, 'minus_xor': 0x0,
        }
        # PART I loop
        matches, rule = self.get_matches([k for k in self.rules.keys() if '$code1' in k])
        opcs = []
        for match in matches:
            idx = match[0]
            data = self.get_func_data(idx)
            opcodes = match[2]
            opc = struct.pack('B', opcodes[-8])
            inc = b'\xFF\x45' + opc
            if inc in data:
                vars['loop_count'] = struct.unpack('I', opcodes[-7: -7 + 4])[0]
            else:
                vars['loop_count'] = struct.unpack('B', opcodes[-4: -4 + 1])[0]
            opcs.append(opc)
            break
        opr1 = b'\xC7\x45'
        opr2 = b'\x89\x45'
        # PART II chunk/junk
        try:
            matches, rule = self.get_matches([k for k in self.rules.keys() if '$code2' in k], data)
        except ValueError:
            data = clean_data(data)
            try:
                matches, rule = self.get_matches([k for k in self.rules.keys() if '$code2' in k], data)
            except ValueError:
                return self.offset_vars(data, vars)
        for match in matches:
            r2addr = match[0]
            opcodes = match[2]
            opr_ch = struct.pack('B', opcodes[2])
            i = data.index(opr1 + opr_ch) + 3
            vars['chunk_size'] = struct.unpack('I', data[i: i + 4])[0]
            opr_ju = struct.pack('B', opcodes[-5])
            opr_ju = opr_ju if opr_ju != opr_ch else struct.pack('B', opr_ch[0] - 4)
            try:
                i = data.index(opr1 + opr_ju) + 3
                vars['junk_size'] = struct.unpack('I', data[i: i + 4])[0]
            except ValueError:
                data.index(b'\x33\xC0\x89\x45' + opr_ju)
                vars['junk_size'] = 0x0
            opcs.append(opr_ch)
            opcs.append(opr_ju)
            break
        # PART III xor
        try:
            matches, rule = self.get_matches([k for k in self.rules.keys() if '$code3' in k], data)
            for match in matches:
                opcodes = match[2]
                if rule == '$code31':
                    vars['minus_xor'] = -1 * struct.unpack('I', opcodes[-5: -5 + 4])[0]
                    ei = -14
                elif rule in ['$code32', '$code33', '$code34']:
                    if b'\x83\xE8' in opcodes:
                        vars['minus_xor'] = -1 * opcodes[-3]
                    ei = -2
                else:
                    vars['minus_xor'] = 0x0
                    ei = 0
                if rule in ['$code33']:
                    opr_xa = struct.pack('B', opcodes[ei])
                elif rule in ['$code35']:
                    opr_xa = struct.pack('B', opcodes[-3])
                else:
                    opr_xa = struct.pack('B', opcodes[4 + ei])
                i = data.index(opr1 + opr_xa) + 3
                vars['xor_add_key'] = struct.unpack('I', data[i: i + 4])[0] + vars['minus_xor']
                if rule == '$code32' and b'\x8B\x45' + opr_xa + b'\x05' in opcodes:
                    vars['xor_key'] = struct.unpack('I', opcodes[4: 4 + 4])[0]
                else:
                    opr_xi = struct.pack('B', opcodes[7 + ei])
                    try:
                        i = data.index(opr1 + opr_xi) + 3
                    except ValueError:
                        i = data.index(opr2 + opr_xi) - 1
                        opr_xi = struct.pack('B', data[i])
                        i = data.index(opr1 + opr_xi) + 3
                    vars['xor_key'] = struct.unpack('I', data[i: i + 4])[0]
                break
        except ValueError:
            idx = data[r2addr:].index(b'\xEB')
            ndata = data[r2addr + idx:]
            try:
                if b'\x83\xE8' in ndata:
                    idx = ndata.index(b'\x83\xE8') + 2
                    vars['minus_xor'] = -1 * ndata[idx]
                elif b'\x48\x03' in ndata:
                    vars['minus_xor'] = -1
                else:
                    rule = '{(8B ?5| 03 ?5| 89 ?5) ?? 2D [4] (8B ?5| 03 ?5| 89 ?5)}'
                    matches = match_rule(rule, ndata)
                    if matches:
                        vars['minus_xor'] = -1 * struct.unpack('I', matches[0][2][4: 4 + 4])[0]
            except ValueError:
                pass
            rule = '{(8B ?5| 03 ?5| 89 ?5) ??}'
            matches = match_rule(rule, ndata)
            res = [struct.pack('B', match[2][2]) for match in matches]
            for r in res:
                if r not in opcs:
                    try:
                        idx = data.index(opr1 + r) + 3
                        if vars['xor_key']:
                            vars['xor_add_key'] = struct.unpack('I', data[idx: idx + 4])[0] + vars['minus_xor']
                            break
                        else:
                            vars['xor_key'] = struct.unpack('I', data[idx: idx + 4])[0]
                    except ValueError:
                        continue
        return vars

    @staticmethod
    def remove_junks(data, chunk_size, junk_size):
        ndata = b''
        i = 0
        while i < len(data):
            ndata += data[i: i + chunk_size]
            i += chunk_size + junk_size
        return fix_dword(ndata)

    def decrypt(self):
        variables = self.get_vars2()
        message("Loop \"Sleep\" count: " + hex(variables['loop_count']).upper())
        message('Init XOR-KEY: ' + hex(variables['xor_key']).upper())
        message("Chunks Size: " + hex(variables['chunk_size']).upper())
        message("Junk Size: " + hex(variables['junk_size']).upper())
        resources = self.get_resources()
        for resource in resources:
            message("Resource Name: " + resource['name'])
            encrypted = self.remove_junks(resource['data'][4:], variables['chunk_size'], variables['junk_size'])
            counter = 0
            mz_decr = b''
            for dw in split_per(encrypted, 4):
                dw = (struct.unpack('I', dw)[0] + counter) & 0xFFFFFFFF
                xortemp = (variables['xor_key'] + variables['xor_add_key'] + counter) & 0xFFFFFFFF
                counter += 4
                mz_decr += struct.pack('I', dw ^ xortemp)
            try:
                idx = mz_decr.index(b'MZ')
                size = get_size(mz_decr[idx:])
            except (ValueError, pefile.PEFormatError):
                continue
            break
        message("Resource Name: " + resource['name'])
        message("Resource Size: " + hex(resource['size']).upper())
        decr_pckg = {'Decryption': variables, 'Resource': resource}
        try:
            return mz_decr[idx: idx + size], decr_pckg
        except UnboundLocalError:
            message(ERRORS['03'])
            return None


class DecryptExecutable86(DecryptExecutable):
    def __init__(self, filepath):
        rules = {
            '$code1': '{C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] (68 ?? ?? ?? ??| 6A ??) E8 [4] FF [2] 81 [6] 7? ?? 68}',
            '$code12': '{C7 45 ?? ?? 00 00 00 (68 ?? ?? ?? ??| 6A ??) E8 [4] FF [2] 81 [6] 7? ?? (68| 8B| C7)}',
            '$code13': '{C7 45 [4] 00 (68 ?? ?? ?? ??| 6A ??) E8 [4] FF [2] (81| 83) [3-6] 7? ?? (68| 8B| C7)}',
            '$code14': '{C7 45 [4] 00 [5-10] E8 [4] FF [2] (81| 83) [3-6] 7? ?? (68| 8B| C7)}',
            '$code15': '{C7 45 [5] C7 45 [5] C7 45 [5] C7 45 [5] FF 45 ?? 81 [6] 7? ?? 6A}',
            '$code16': '{C7 45 [4] 00 E8 [4] FF [2] (81| 83) [3-6] 7? ?? (68| 8B| C7)}',
            '$code17': '{C7 45 [5] 81 [6] 7? [0-3] E8 [4-20] 81 [6] 7? ?? ??}',
            '$code2': '{8B 4D ?? E8 [4] [3-30] 01 [2] 8B 45 ?? 01 45 ?? 8B 45 ?? 01 45 ?? E?}',
            '$code21': '{8B 4D ?? E8 [0-34] 03 [0-32] (03 ?? ??| 8B 45 ??) ?? ?? ?? ??}',
            '$code22': '{03 45 ?? 50 E8 [4-60] 8B 45 ?? 01 45 ?? EB}',
            '$code3': '{(01 02| ?? FF) 8B 45 ?? 03 45 ?? [0-6] 8B 55 ?? 31 02}',
            '$code31': '{2B D8 8B [2] 89 18 [0-10] 8B [2] 03 [2] 2D [4] 03}',
            '$code32': '{8B 45 ?? (03 45 ??| 05 [3] 00) [0-3] 03 45}',
            '$code33': '{8B 45 ?? 03 45 ?? 89 45 ?? [6] 01 02 [10-60] 8B 45 ?? 03}',
            '$code34': '{8B 55 ?? 03 55 ?? 03 55 [0-6] 33}',
            '$code35': '{(?? ?? ?? 8B D8| 00 00) 8B 45 ?? 03 45 ?? (03 D8| 89) [5-70] 8B 45 ?? 03 45}',

            '$codev2': '{8B ?? [4] E8 [4] [0-50] (03| 01) [0-50] EB}',
            '$codev3': '{8B ?5 [4] 81 ?? [4] 03}',
            '$codev31': '{?? A1 [4] 03 [5] 2D [4] 03}',
        }
        DecryptExecutable.__init__(self, filepath, 0x32, rules)


class DecryptExecutable64(DecryptExecutable):
    def __init__(self, filepath):
        rules = {
            '$scode1': ERRORS['04'],
        }
        DecryptExecutable.__init__(self, filepath, 0x64, rules)
