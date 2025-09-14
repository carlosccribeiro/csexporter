#!/usr/bin/env python3
"""
Menu principal para gerenciar exports e clientes do CrowdStrike.
Opção 1: Exportar (submenu com exports, seleciona cliente com auto-completar).
Opção 2: Clientes (submenu CRUD com auto-completar).
Opção 3: Sair.
O ambiente virtual deve estar ativado antes de rodar.
"""

import subprocess
import sys
import os
import json
import readline

# Mapeamento entre opções e scripts com caminhos relativos
options = {
    "1": ("Export Prevention Policies", "exportpp.py"),
    "2": ("Export USB Policies", "exportusb.py"),
    "3": ("Export Response Policies", "exportrp.py"),
    "4": ("Export Sensor Update Policies", "exportsup.py"),
    "5": ("Export Exclusions", "exportexclusions.py"),
    "6": ("Export Host Groups", "exporthostgroups.py"),
    "7": ("Export IOA Rules", "exportioarules.py"),
    "8": ("Export IOC", "exportiocs.py"),
    "9": ("Export All", None),
    "\n0": ("Voltar", None),
}

ENV_FILE = ".env"
completer_options = []

def load_client_configs():
    client_configs = {}
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("CLIENT_CONFIGS="):
                    config_str = line.split("CLIENT_CONFIGS=", 1)[1]
                    if config_str:
                        try:
                            client_configs = json.loads(config_str)
                        except json.JSONDecodeError:
                            print("Erro ao decodificar CLIENT_CONFIGS. O arquivo .env pode estar corrompido.")
                            client_configs = {}
    return client_configs

def save_client_configs(client_configs):
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(f"CLIENT_CONFIGS={json.dumps(client_configs)}\n")

def update_env_for_client(client_name, client_configs):
    config = client_configs.get(client_name)
    if not config:
        print("Cliente não encontrado.")
        return False

    # Carrega o conteúdo atual do .env para preservar CLIENT_CONFIGS
    current_content = {}
    if os.path.isfile(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("CLIENT_CONFIGS="):
                    key, value = line.split("=", 1)
                    current_content[key.strip()] = value.strip()

    # Atualiza apenas as configurações ativas, mantendo CLIENT_CONFIGS
    env_content = [
        f"FALCON_CLIENT_ID={config['FALCON_CLIENT_ID']}",
        f"FALCON_CLIENT_SECRET={config['FALCON_CLIENT_SECRET']}",
        f"FALCON_BASE_URL={config['FALCON_BASE_URL']}",
        f"CLIENT_NAME={client_name}",
    ]
    env_content.extend([f"{k}={v}" for k, v in current_content.items() if k not in ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL", "CLIENT_NAME"]])

    # Regrava o .env com CLIENT_CONFIGS mantido
    all_configs = load_client_configs()
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(f"CLIENT_CONFIGS={json.dumps(all_configs)}\n")
        f.write("\n".join(env_content))
    return True

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def completer(text, state):
    global completer_options
    # Converte o texto de entrada e as opções para minúsculas para ignorar case
    text = text.lower()
    options = [opt for opt in completer_options if opt.lower().startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

def input_with_autocomplete(prompt, options):
    global completer_options
    completer_options = options
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    user_input = input(prompt)
    readline.set_completer(None)
    return user_input

def run_script(script):
    if not os.path.isfile(script):
        print(f"\n❌ Erro: O script '{script}' não foi encontrado na pasta atual.\n")
        return

    print(f"\n🚀 Executando {script}...\n")
    try:
        subprocess.run([sys.executable, script], check=True)
        print(f"\n✅ {script} finalizado com sucesso!\n")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Erro ao executar {script}: {e}\n")

def cadastrar_cliente():
    clear_screen()
    print("===== CRIAR CLIENTE =====")
    client_name = input("Digite o nome do Cliente: ").strip()
    client_id = input("Digite o Client ID: ").strip()
    client_secret = input("Digite o Client Secret: ").strip()

    while True:
        cloud_choice = input("Digite o Cloud (1 = us-1, 2 = us-2): ").strip()
        if cloud_choice == "1":
            cloud = "us-1"
            break
        elif cloud_choice == "2":
            cloud = "us-2"
            break
        else:
            print("⚠️ Opção inválida, escolha 1 ou 2.")

    falcon_base_url = {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
    }.get(cloud, "https://api.crowdstrike.com")

    client_configs = load_client_configs()
    if client_name in client_configs:
        print("Cliente já existe. Use Editar para modificar.")
    else:
        client_configs[client_name] = {
            "FALCON_CLIENT_ID": client_id,
            "FALCON_CLIENT_SECRET": client_secret,
            "FALCON_BASE_URL": falcon_base_url,
        }
        save_client_configs(client_configs)
        print(f"\n✅ Cliente '{client_name}' criado com sucesso!\n")
    input("Pressione ENTER para voltar...")
    clear_screen()

def editar_cliente(client_configs):
    clear_screen()
    print("===== EDITAR CLIENTE =====")
    if not client_configs:
        print("Nenhum cliente cadastrado.")
        input("Pressione ENTER para voltar...")
        clear_screen()
        return
    client_name = input_with_autocomplete("Digite o nome do cliente a editar: ", list(client_configs.keys()))
    if client_name not in client_configs:
        print("Cliente não encontrado.")
        input("Pressione ENTER para voltar...")
        clear_screen()
        return

    config = client_configs[client_name]
    client_id = input(f"Client ID atual ({config['FALCON_CLIENT_ID']}): ").strip() or config['FALCON_CLIENT_ID']
    client_secret = input(f"Client Secret atual (***): ").strip() or config['FALCON_CLIENT_SECRET']
    current_cloud = "us-1" if config['FALCON_BASE_URL'] == "https://api.crowdstrike.com" else "us-2"
    cloud_choice = input(f"Cloud atual ({current_cloud}): (1 = us-1, 2 = us-2) ").strip() or current_cloud
    falcon_base_url = {
        "1": "https://api.crowdstrike.com",
        "2": "https://api.us-2.crowdstrike.com",
    }.get(cloud_choice, config['FALCON_BASE_URL'])

    client_configs[client_name] = {
        "FALCON_CLIENT_ID": client_id,
        "FALCON_CLIENT_SECRET": client_secret,
        "FALCON_BASE_URL": falcon_base_url,
    }
    save_client_configs(client_configs)
    print("\n✅ Cliente editado com sucesso!\n")
    input("Pressione ENTER para voltar...")
    clear_screen()

def listar_clientes(client_configs):
    clear_screen()
    print("===== LISTAR CLIENTES =====")
    if not client_configs:
        print("Nenhum cliente cadastrado.")
    else:
        for client in client_configs:
            print(f"- {client}")
    input("Pressione ENTER para voltar...")
    clear_screen()

def deletar_cliente(client_configs):
    clear_screen()
    print("===== DELETAR CLIENTE =====")
    if not client_configs:
        print("Nenhum cliente cadastrado.")
        input("Pressione ENTER para voltar...")
        clear_screen()
        return
    client_name = input_with_autocomplete("Digite o nome do cliente a deletar: ", list(client_configs.keys()))
    if client_name not in client_configs:
        print("Cliente não encontrado.")
        input("Pressione ENTER para voltar...")
        clear_screen()
        return

    del client_configs[client_name]
    save_client_configs(client_configs)
    print("\n✅ Cliente deletado com sucesso!\n")
    input("Pressione ENTER para voltar...")
    clear_screen()

def submenu_exportar(client_configs):
    clear_screen()
    while True:
        print("===== MENU EXPORTAR =====\n")
        for key, (desc, _) in options.items():
            print(f"{key}. {desc}")
        print("\n═══════════════════════════\n")

        escolha = input("Digite o número da opção desejada: ").strip()

        if escolha == "0":
            clear_screen()
            break
        elif escolha in options:
            desc, script = options[escolha]
            if client_configs:
                client_name = input_with_autocomplete("Digite o nome do cliente: ", list(client_configs.keys()))
                if client_name not in client_configs:
                    print("Cliente não encontrado.")
                    input("Pressione ENTER para continuar...")
                    clear_screen()
                    continue
                if update_env_for_client(client_name, client_configs):
                    if escolha == "9":  # ALL
                        for key, (d, s) in options.items():
                            if s:  # pula "All"
                                run_script(s)
                    else:
                        run_script(script)
            else:
                print("Nenhum cliente cadastrado. Cadastre um cliente primeiro.")
                input("Pressione ENTER para continuar...")
                clear_screen()
                continue
        else:
            print("⚠️ Opção inválida! Tente novamente.")

def submenu_clientes():
    client_configs = load_client_configs()
    clear_screen()
    while True:
        print("===== MENU CLIENTES =====\n")
        print("1. Criar Cliente")
        print("2. Editar Cliente")
        print("3. Listar Clientes")
        print("4. Deletar Cliente")
        print("\n0. Voltar\n")
        print("═══════════════════════════\n")

        escolha = input("Digite o número da opção desejada: ").strip()

        if escolha == "0":
            clear_screen()
            break
        elif escolha == "1":
            cadastrar_cliente()
        elif escolha == "2":
            editar_cliente(client_configs)
        elif escolha == "3":
            listar_clientes(client_configs)
        elif escolha == "4":
            deletar_cliente(client_configs)
        else:
            print("⚠️ Opção inválida! Tente novamente.")

def menu_principal():
    clear_screen()
    while True:
        client_configs = load_client_configs()
        print("\n███████╗███╗  ███╗██████╗  ██████╗ ██████╗ ████████╗████████╗██████╗ ") 
        print("██╔════╝╚███╗███╔╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔═════╝██╔══██╗") 
        print("█████╗   ╚█████╔╝ ██████╔╝██║   ██║██████╔╝   ██║   █████╗   ██████╔╝") 
        print("██╔══╝   ███╔███╗ ██╔═══╝ ██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔══██╗") 
        print("███████╗███╔╝ ███╗██║     ╚██████╔╝██║  ██║   ██║   ████████╗██║  ██║") 
        print("╚══════╝╚══╝  ╚══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═══════╝╚═╝  ╚═╝")
        print("═════ MENU PRINCIPAL ════════════════════════════════════════════════\n")
        print("1. Exportar")
        print("2. Clientes")
        print("\n3. Sair\n")
        print("═════════════════════════════════════════════════════════════════════\n")

        escolha = input("Digite o número da opção desejada: ").strip()

        if escolha == "1":
            submenu_exportar(client_configs)
        elif escolha == "2":
            submenu_clientes()
        elif escolha == "3":
            print("👋 Saindo do sistema...")
            break
        else:
            print("⚠️ Opção inválida! Tente novamente.")

# Executa o menu principal
if __name__ == "__main__":
    clear_screen()
    menu_principal()