#!/usr/bin/python3

import argparse
import json
import jmespath
import functools
import operator
import os
from pprint import pprint


class SysWhispers(object):

    def __init__(self):
        self.typedefs: list = json.load(open('./data/typedefs.json'))
        self.prototypes: dict = json.load(open('./data/prototypes.json'))
        self.syscall_numbers: dict = json.load(open('./data/syscall_numbers.json'))

        self.version_syscall_map = lambda function_name: {
            'Windows XP': [{
                'version': '5.X.XXXX',
                'description': 'Windows XP and Server 2003',
                'jmespath': f'{function_name}."Windows XP".SP2'
            }],

            'Windows Vista': [{
                'version': '6.0.6000',
                'description': 'Windows Vista SP0',
                'jmespath': f'{function_name}."Windows Vista".SP0'
            }, {
                'version': '6.0.6001',
                'description': 'Windows Vista SP1 and Server 2008 SP0',
                'jmespath': f'{function_name}."Windows Vista".SP1'
            }, {
                'version': '6.0.6002',
                'description': 'Windows Vista SP2 and Server 2008 SP2',
                'jmespath': f'{function_name}."Windows Vista".SP2'
            }],

            'Windows 7': [{
                'version': '6.1.7600',
                'description': 'Windows 7 SP0',
                'jmespath': f'{function_name}."Windows 7".SP0'
            }, {
                'version': '6.1.7601',
                'description': 'Windows 7 SP1 and Server 2008 R2 SP0',
                'jmespath': f'{function_name}."Windows 7".SP1'
            }],

            'Windows 8': [{
                'version': '6.2.XXXX',
                'description': 'Windows 8 and Server 2012',
                'jmespath': f'{function_name}."Windows 8"."8.0"'
            }, {
                'version': '6.3.XXXX',
                'description': 'Windows 8.1 and Server 2012 R2',
                'jmespath': f'{function_name}."Windows 8"."8.1"'
            }],

            'Windows 10': [{
                'version': '10.0.10240',
                'description': 'Windows 10.0.10240 (1507)',
                'jmespath': f'{function_name}."Windows 10"."1507"'
            }, {
                'version': '10.0.10586',
                'description': 'Windows 10.0.10586 (1511)',
                'jmespath': f'{function_name}."Windows 10"."1511"'
            }, {
                'version': '10.0.14393',
                'description': 'Windows 10.0.14393 (1607)',
                'jmespath': f'{function_name}."Windows 10"."1607"'
            }, {
                'version': '10.0.15063',
                'description': 'Windows 10.0.15063 (1703)',
                'jmespath': f'{function_name}."Windows 10"."1703"'
            }, {
                'version': '10.0.16299',
                'description': 'Windows 10.0.16299 (1709)',
                'jmespath': f'{function_name}."Windows 10"."1709"'
            }, {
                'version': '10.0.17134',
                'description': 'Windows 10.0.17134 (1803)',
                'jmespath': f'{function_name}."Windows 10"."1803"'
            }, {
                'version': '10.0.17763',
                'description': 'Windows 10.0.17763 (1809)',
                'jmespath': f'{function_name}."Windows 10"."1809"'
            }, {
                'version': '10.0.18362',
                'description': 'Windows 10.0.18362 (1903)',
                'jmespath': f'{function_name}."Windows 10"."1903"'
            }, {
                'version': '10.0.18363',
                'description': 'Windows 10.0.18363 (1909)',
                'jmespath': f'{function_name}."Windows 10"."1909"'
            }, {
                'version': '10.0.19041',
                'description': 'Windows 10.0.19041 (2004)',
                'jmespath': f'{function_name}."Windows 10"."2004"'
            }, {
                'version': '10.0.19042',
                'description': 'Windows 10.0.19042 (20H2)',
                'jmespath': f'{function_name}."Windows 10"."20H2"'
            }, {
                'version': '10.0.19043',
                'description': 'Windows 10.0.19043 (21H1)',
                'jmespath': f'{function_name}."Windows 10"."21H1"'
            }]
        }

    def generate(self, function_names: list = (), versions: list = (), basename: str = 'syscalls'):
        if not function_names:
            function_names = list(self.syscall_numbers.keys())

        excluded_functions = []

        # Write ASM file.
        with open(f'{basename}.asm', 'wb') as hnd:
            hnd.write(b'.code\n\n')
            for function_name in function_names:
                try:
                    hnd.write((self._get_function_asm_code(function_name, versions) + '\n').encode())
                except ValueError as incompatible_function:
                    print(f'WARNING: {incompatible_function}')
                    excluded_functions.append(function_name)
            hnd.write(b'end')

        function_names = list(set(function_names) - set(excluded_functions))
        if not function_names:
            os.remove(f'{basename}.asm')
            print('ERROR:   No compatible functions found. Exiting...')
            return
        elif excluded_functions:
            print()

        # Write header file.
        with open(f'{basename}.h', 'wb') as hnd:
            hnd.write(b'#pragma once\n\n#include <Windows.h>\n\n')
            for typedef in self._get_typedefs(function_names):
                hnd.write(typedef.encode() + b'\n\n')
            for function_name in function_names:
                hnd.write((self._get_function_prototype(function_name) + '\n\n').encode())

        print('Complete! Files written to:')
        print(f'\t{basename}.asm')
        print(f'\t{basename}.h')

    def get_version_compatibility(self, versions: list) -> dict:
        version_compatibility = {}
        for version in versions:
            version_compatibility[version] = list(filter(lambda f: version in self.syscall_numbers[f],
                                                         [f for f in self.syscall_numbers]))
        return version_compatibility

    def get_function_compatibility(self, function_names: list) -> dict:
        function_compatibility = {}
        for function_name in function_names:
            function_compatibility[function_name] = [v for v in self.syscall_numbers[function_name].keys()
                                                     if v in self.version_syscall_map(function_name).keys()]
        return function_compatibility

    def _get_typedefs(self, function_names: list) -> list:
        def _names_to_ids(names: list) -> list:
            return [next(i for i, t in enumerate(self.typedefs) if n in t['identifiers']) for n in names]

        # Determine typedefs to use.
        used_typedefs = []
        for function_name in function_names:
            for param in self.prototypes[function_name]['params']:
                if list(filter(lambda t: param['type'] in t['identifiers'], self.typedefs)):
                    if param['type'] not in used_typedefs:
                        used_typedefs.append(param['type'])

        # Resolve typedef dependencies.
        i = 0
        typedef_layers = {i: _names_to_ids(used_typedefs)}
        while True:
            # Identify dependencies of current layer.
            more_dependencies = []
            for typedef_id in typedef_layers[i]:
                more_dependencies += self.typedefs[typedef_id]['dependencies']
            more_dependencies = list(set(more_dependencies))  # Remove duplicates.

            if more_dependencies:
                # Create new layer.
                i += 1
                typedef_layers[i] = _names_to_ids(more_dependencies)
            else:
                # Remove duplicates between layers.
                for k in range(len(typedef_layers) - 1):
                    typedef_layers[k] = set(typedef_layers[k]) - set(typedef_layers[k + 1])
                break

        # Get code for each typedef.
        typedef_code = []
        for i in range(max(typedef_layers.keys()), -1, -1):
            for j in typedef_layers[i]:
                typedef_code.append(self.typedefs[j]['definition'])
        return typedef_code

    def _get_function_prototype(self, function_name: str) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'EXTERN_C NTSTATUS {function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                signature += '\n\t'
                signature += 'IN ' if param['in'] else ''
                signature += 'OUT ' if param['out'] else ''
                signature += f'{param["type"]} {param["name"]}'
                signature += ' OPTIONAL' if param['optional'] else ''
                signature += ',' if i < num_params - 1 else ');'
        else:
            signature += ');'

        return signature

    def _get_function_asm_code(self, function_name: str, versions: list = ()) -> str:
        # Check if given function is in syscall map.
        if function_name not in self.syscall_numbers:
            raise ValueError('Invalid function name provided.')

        # If no versions list is provided, support all compatible versions.
        if not versions:
            versions = [v for v in self.syscall_numbers[function_name].keys()
                        if v in self.version_syscall_map(function_name).keys()]

        # Check if given function is compatible with given Windows versions.
        compatible_versions = []
        incompatible_versions = []
        for version in versions:
            if any(isinstance(jmespath.search(build['jmespath'], self.syscall_numbers), int)
                   for build in self.version_syscall_map(function_name)[version]):
                compatible_versions.append(version)
            else:
                incompatible_versions.append(version)
        if incompatible_versions:
            raise ValueError(f'{function_name} is not compatible with {", ".join(incompatible_versions)}.')

        # Generate 64-bit ASM code.
        code = ''
        code += f'{function_name} PROC\n'
        code += '\tmov rax, gs:[60h]'.ljust(len(function_name) + 24)
        code += '; Load PEB into RAX.\n'

        # Code to check major version.
        code += f'{function_name}_Check_X_X_XXXX:'.ljust(len(function_name) + 31)
        code += '; Check major version.\n'
        if 'Windows XP' in compatible_versions:
            code += '\tcmp dword ptr [rax+118h], 5\n'
            code += f'\tje  {function_name}_SystemCall_5_X_XXXX\n'
        if any(v in compatible_versions for v in ['Windows Vista', 'Windows 7', 'Windows 8']):
            code += '\tcmp dword ptr [rax+118h], 6\n'
            code += f'\tje  {function_name}_Check_6_X_XXXX\n'
        if 'Windows 10' in compatible_versions:
            code += '\tcmp dword ptr [rax+118h], 10\n'
            code += f'\tje  {function_name}_Check_10_0_XXXX\n'
        code += f'\tjmp {function_name}_SystemCall_Unknown\n'

        # Code to check minor version for Vista/7/8.
        if any(v in compatible_versions for v in ['Windows Vista', 'Windows 7', 'Windows 8']):
            code += f'{function_name}_Check_6_X_XXXX:'.ljust(len(function_name) + 31)
            code += '; Check minor version for Windows Vista/7/8.\n'
            if 'Windows Vista' in compatible_versions:
                code += '\tcmp dword ptr [rax+11ch], 0\n'
                code += f'\tje  {function_name}_Check_6_0_XXXX\n'
            if 'Windows 7' in compatible_versions:
                code += '\tcmp dword ptr [rax+11ch], 1\n'
                code += f'\tje  {function_name}_Check_6_1_XXXX\n'
            if 'Windows 8' in compatible_versions:
                for build in self.version_syscall_map(function_name)['Windows 8']:
                    if isinstance(jmespath.search(build['jmespath'], self.syscall_numbers), int):
                        code += f'\tcmp dword ptr [rax+11ch], {build["version"][2]}\n'
                        code += f'\tje  {function_name}_SystemCall_{build["version"].replace(".", "_")}\n'
            code += f'\tjmp {function_name}_SystemCall_Unknown\n'

        # Code to check build number for Windows Vista.
        if 'Windows Vista' in compatible_versions:
            code += f'{function_name}_Check_6_0_XXXX:'.ljust(len(function_name) + 31)
            code += '; Check build number for Windows Vista.\n'
            for build in self.version_syscall_map(function_name)['Windows Vista']:
                if jmespath.search(build['jmespath'], self.syscall_numbers):
                    code += f'\tcmp word ptr [rax+120h], {build["version"].split(".")[-1]}\n'
                    code += f'\tje  {function_name}_SystemCall_{build["version"].replace(".", "_")}\n'
            code += f'\tjmp {function_name}_SystemCall_Unknown\n'

        # Code to check build number for Windows 7.
        if 'Windows 7' in compatible_versions:
            code += f'{function_name}_Check_6_1_XXXX:'.ljust(len(function_name) + 31)
            code += '; Check build number for Windows 7.\n'
            for build in self.version_syscall_map(function_name)['Windows 7']:
                if jmespath.search(build['jmespath'], self.syscall_numbers):
                    code += f'\tcmp word ptr [rax+120h], {build["version"].split(".")[-1]}\n'
                    code += f'\tje  {function_name}_SystemCall_{build["version"].replace(".", "_")}\n'
            code += f'\tjmp {function_name}_SystemCall_Unknown\n'

        # Code to check build number for Windows 10.
        if 'Windows 10' in compatible_versions:
            code += f'{function_name}_Check_10_0_XXXX:'.ljust(len(function_name) + 31)
            code += '; Check build number for Windows 10.\n'
            for build in self.version_syscall_map(function_name)['Windows 10']:
                if jmespath.search(build['jmespath'], self.syscall_numbers):
                    code += f'\tcmp word ptr [rax+120h], {build["version"].split(".")[-1]}\n'
                    code += f'\tje  {function_name}_SystemCall_{build["version"].replace(".", "_")}\n'
            code += f'\tjmp {function_name}_SystemCall_Unknown\n'

        # Code to set syscall values.
        for version in compatible_versions:
            for build in self.version_syscall_map(function_name)[version]:
                if isinstance(jmespath.search(build['jmespath'], self.syscall_numbers), int):
                    code += f'{function_name}_SystemCall_{build["version"].replace(".", "_")}:'.ljust(
                        len(function_name) + 31)
                    code += f'; {build["description"]}\n'
                    code += '\tmov eax, %04xh\n' % jmespath.search(build['jmespath'], self.syscall_numbers)
                    code += f'\tjmp {function_name}_Epilogue\n'

        # What to do when syscall is not found.
        code += f'{function_name}_SystemCall_Unknown:'.ljust(len(function_name) + 31)
        code += '; Unknown/unsupported version.\n'
        code += '\tret\n'

        # Send the syscall and return.
        code += f'{function_name}_Epilogue:\n'
        code += '\tmov r10, rcx\n'
        code += '\tsyscall\n'
        code += '\tret\n'
        code += f'{function_name} ENDP\n'

        return code


if __name__ == '__main__':

    print(
        "                                                      \n"
        "  ,         ,       ,_ /_   .  ,   ,_    _   ,_   ,   \n"
        "_/_)__(_/__/_)__/_/_/ / (__/__/_)__/_)__(/__/ (__/_)__\n"
        "      _/_                         /                   \n"
        "     (/                          /   @Jackson_T, 2019 \n\n"
        "SysWhispers: Why call the kernel when you can whisper?\n"
    )

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--preset', help='Preset ("all", "common")', required=False)
    parser.add_argument('-f', '--functions', help='Comma-separated functions', required=False)
    parser.add_argument('-v', '--versions', help='Comma-separated versions (XP, Vista, 7, 8, 10)', required=False)
    parser.add_argument('-o', '--out-file', help='Output basename (w/o extension)', required=True)
    args = parser.parse_args()

    sw = SysWhispers()

    if args.preset == 'all':
        print('All functions selected.\n')
        sw.generate(basename=args.out_file)

    elif args.preset == 'common':
        print('Common functions selected.\n')
        sw.generate(
            ['NtCreateProcess',
             'NtCreateThreadEx',
             'NtOpenProcess',
             'NtOpenThread',
             'NtSuspendProcess',
             'NtSuspendThread',
             'NtResumeProcess',
             'NtResumeThread',
             'NtGetContextThread',
             'NtSetContextThread',
             'NtClose',
             'NtReadVirtualMemory',
             'NtWriteVirtualMemory',
             'NtAllocateVirtualMemory',
             'NtProtectVirtualMemory',
             'NtFreeVirtualMemory',
             'NtQuerySystemInformation',
             'NtQueryDirectoryFile',
             'NtQueryInformationFile',
             'NtQueryInformationProcess',
             'NtQueryInformationThread',
             'NtCreateSection',
             'NtOpenSection',
             'NtMapViewOfSection',
             'NtUnmapViewOfSection',
             'NtAdjustPrivilegesToken',
             'NtDeviceIoControlFile',
             'NtQueueApcThread',
             'NtWaitForMultipleObjects'],
            ['Windows 7',
             'Windows 8',
             'Windows 10'],
            basename=args.out_file)

    elif args.preset:
        print('ERROR: Invalid preset provided. Must be "all" or "common".')

    elif not args.functions and not args.versions:
        print('ERROR:   --preset XOR --functions AND/OR --versions switches must be specified.\n')
        print('EXAMPLE: ./syswhispers.py --preset common --out-file syscalls_common')
        print(
            'EXAMPLE: ./syswhispers.py --functions NtProtectVirtualMemory,NtWriteVirtualMemory --out-file syscalls_mem')
        print('EXAMPLE: ./syswhispers.py --versions 7,8,10 --out-file syscalls_78X')

    else:
        versions_map = {
            'xp': 'Windows XP',
            'vista': 'Windows Vista',
            '7': 'Windows 7',
            '8': 'Windows 8',
            '10': 'Windows 10'
        }

        functions = args.functions.split(',') if args.functions else []
        versions = [versions_map[v] for v in args.versions.lower().split(',') if
                    v in versions_map] if args.versions else []
        sw.generate(functions, versions, args.out_file)
