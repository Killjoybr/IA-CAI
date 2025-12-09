import os
import dotenv
import autogen 
import subprocess

from typing import Literal
from typing_extensions import Annotated

dotenv.load_dotenv()
api_key = os.getenv('API_KEY')

# config_list = [
#     {
#         "model": "qwen/qwen3-32b",
#         "api_key": api_key,
#         "api_type": "groq"
#     }
# ]

llm_config = [
    {
        "api_key": api_key,
        "api_type": "groq",
        "model": "qwen/qwen3-32b",
        "config_list": {
        },
        "timeout": 120
    }
]

# definicao do agente
CAI = autogen.AssistantAgent(name = 'autoCai', system_message = 'Você é um pentester sênior, use APENAS as funções que você recebeu. Responda TERMINATE quando terminar a tarefa', llm_config=llm_config)

# agente user proxy
proxy_name = 'user_proxy'
user_proxy = autogen.UserProxyAgent(
    proxy_name,
    is_termination_msg = lambda x: x.get('content','') and x.get('content','').rstrip().endswith('TERMINATE'),
    human_input_mode = 'NEVER',
    max_consecutive_auto_reply = 1,
    code_execution_config = False
)

TypeSymbol = Literal['']

# registro de ferramentas
@user_proxy.register_for_execution()
# registro de assinaturas das ferramentas do agente CAI

@CAI.register_for_llm(description='Create file based on previous output')
def create_file(
    texto: Annotated[str, "Grava arquivo com output anterior, note que se ouver espacos em branco substitua-os por _"]
):
    try:
        subprocess.run(['./createFile.sh', texto], shell=True)
        return 'Arquivo criado'
    except:
        return 'Não consegui criar o arquivo'
# @CAI.register_for_llm(description='Get content from user')
# def get_content(
#         content: Annotated[str, "Captura a palavra que o usuario quer salvar"]
#     )-> str:
#     return f'{content}'

# iniciando a conversa
user_proxy.initiate_chat(
    CAI,
    message = 'Crie um arquivo meu nome: Joao da Silva'
)