using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using static System.Console;

namespace GSDBIM2_ATV2
{
    internal class Program
    {
        static void Main(string[] args)
        {
                WindowsIdentity identity = ExibeInfoIdentity();
                WindowsPrincipal principal = ExibeInfoPrincipal(identity);
                ExibeInfoClaims(principal.Claims);
                ReadLine();   
        }
        public static WindowsIdentity ExibeInfoIdentity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            if (identity == null)
            {
                WriteLine("Não é um Windows Identity");
                return null;
            }
            WriteLine($"Tipo de Identity : {identity}"); WriteLine("Mostra o identificador de segurança (número único que o Windows usa para identificar cada usuário, grupo ou conta de máquina no sistema.) ou a representação do usuário atual no sistema."); WriteLine("------------------------------------------------------------------------------------------------------------");

            WriteLine($"\nNome : {identity.Name}"); WriteLine("Nome do usuário logado"); WriteLine("------------------------------------------------------------------------------------------------------------");

            WriteLine($"\nAutenticado : {identity.IsAuthenticated}"); WriteLine("Informa se o usuário atual está logado com uma conta válida no Windows."); WriteLine("------------------------------------------------------------------------------------------------------------");
            
            WriteLine($"\nTipo de Autenticação : {identity.AuthenticationType}");WriteLine("Método usado para autentificação (Kerberos é o protocolo usado pelo Windows para autenticar o usuário de forma segura e rápida em redes corporativas.\r\nEle permite que o usuário acesse vários recursos da rede sem precisar se autenticar toda hora.)"); WriteLine("------------------------------------------------------------------------------------------------------------");
            
            WriteLine($"\nÉ usuário Anônimo ? : {identity.IsAnonymous}"); WriteLine("Verifica e exibe se o usuário atual é anônimo (ou seja, não está logado no sistema com uma conta)."); WriteLine("------------------------------------------------------------------------------------------------------------");

            WriteLine($"\nToken de acesso : " + $"{identity.AccessToken.DangerousGetHandle()}"); WriteLine("Mostra o número identificador (handle) do token de segurança do usuário logado, usado internamente pelo Windows para controlar permissões."); WriteLine("------------------------------------------------------------------------------------------------------------");

            WriteLine();
            return identity;
        }

        public static WindowsPrincipal ExibeInfoPrincipal(WindowsIdentity identity)
        {
            WriteLine("Informação do Principal");
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal == null)
            {
                WriteLine("Não é um Windows Principal");
                return null;
            }
            WriteLine($"É Usuário ? {principal.IsInRole(WindowsBuiltInRole.User)}");
            WriteLine($"É Administrador ? {principal.IsInRole(WindowsBuiltInRole.Administrator)}");
            WriteLine("Verifica se o usuário atual é um “usuário comum” ou um “administrador” do Windows, com base na identidade fornecida. Depois, retorna esse objeto principal para uso posterior."); WriteLine("------------------------------------------------------------------------------------------------------------");
            return principal;
        }

        public static void ExibeInfoClaims(IEnumerable<Claim> claims)
        {
     
            WriteLine("Declarações (Claims)");
            WriteLine("Uma claim (declaração) é uma afirmação sobre um sujeito (usuário ou entidade),");
            WriteLine("que contém informações importantes para autenticação e autorização no sistema.");
            WriteLine("Cada claim possui um emissor (Issuer), que é a autoridade responsável por emitir essa informação.");
            WriteLine("Além disso, claims podem ter propriedades adicionais que detalham seu contexto.");
            WriteLine("\nO sistema vai listar as claims (declarações) do usuário.");
            WriteLine("------------------------------------------------------------------------------------------------------------");

            foreach (var claim in claims)
            {
                WriteLine($"\nAssunto : {claim.Subject}");
                WriteLine("Exibe o assunto da claim — quem é o objeto ou entidade relacionado a essa informação.");

                WriteLine($"\nEmissor : {claim.Issuer}");
                WriteLine("Exibe quem emitiu essa claim — autoridade responsável pela informação.");

                // Explicação padrão do emissor principal
                if (claim.Issuer.Equals("AD AUTHORITY", StringComparison.OrdinalIgnoreCase))
                {
                    WriteLine("\nEmissor AD AUTHORITY: Claim emitida pela Active Directory (AD).");
                    WriteLine("Autoridade responsável pela autenticação em ambientes Windows corporativos.");
                }
                else if (claim.Issuer.Equals("NT AUTHORITY", StringComparison.OrdinalIgnoreCase))
                {
                    WriteLine("\nEmissor NT AUTHORITY: Claim emitida internamente pelo sistema Windows.");
                    WriteLine("Esta autoridade é responsável por informações internas do sistema operacional.");
                }
                else
                {
                    WriteLine("\nEmissor desconhecido ou personalizado.");
                    WriteLine("Não foi possível identificar a autoridade emissora da claim.");
                }

                // Agora interpretamos as propriedades adicionais para detalhar o 'windowssubauthority'
                if (claim.Properties.TryGetValue("http://schemas.microsoft.com/ws/2008/06/identity/claims/windowssubauthority", out var subAuthority))
                {
                    WriteLine($"\nPropriedade windowssubauthority: {subAuthority}");
                    switch (subAuthority.ToString())
                    {
                        case "NTAuthority":
                            WriteLine("\nNTAuthority: Autoridade do sistema local Windows.");
                            WriteLine("Esta é uma autoridade interna do sistema operacional Windows responsável por gerenciar identidades e permissões locais.");
                            WriteLine("Claims emitidas por NTAuthority representam contas internas do Windows, como SYSTEM, Administradores locais ou serviços do sistema.");
                            WriteLine("Ela controla o acesso a recursos locais do computador e operações que requerem privilégios do sistema.");
                            break;

                        case "LocalAuthority":
                            WriteLine("\nLocalAuthority: Autoridade local da rede ou domínio.");
                            WriteLine("Representa uma autoridade de autenticação que atua dentro de um contexto de rede restrito, como um domínio Active Directory ou um ambiente local.");
                            WriteLine("Claims emitidas por LocalAuthority são usadas para representar usuários e entidades autenticadas dentro desse domínio ou rede local, controlando acessos e permissões específicas do ambiente corporativo.");
                            WriteLine("Essa autoridade gerencia a identidade e as permissões em um escopo restrito, permitindo políticas de segurança locais.");
                            break;

                        case "WorldAuthority":
                            WriteLine("\nWorldAuthority: Autoridade externa ou global.");
                            WriteLine("Refere-se a uma autoridade de autenticação que opera em um escopo global ou externo ao ambiente local, como provedores de identidade na internet.");
                            WriteLine("Claims emitidas por WorldAuthority representam identidades federadas ou externas ao domínio local, permitindo acesso a sistemas que aceitam autenticação global, como serviços cloud ou federados.");
                            WriteLine("É usada para integrar identidades externas e possibilitar autenticação em múltiplos domínios ou ambientes distribuídos.");
                            break;

                        default:
                            WriteLine("\nSubauthoridade desconhecida.");
                            WriteLine("Não foi possível identificar o tipo específico da autoridade emissora dessa claim.");
                            break;
                    
                }
                }

                // Exibir demais propriedades
                foreach (var prop in claim.Properties)
                {
                    // Ignorar o windowssubauthority já exibido
                    if (prop.Key == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowssubauthority")
                        continue;

                    WriteLine($"\nProperty: {prop.Key} {prop.Value}");
                    WriteLine("Mostra propriedades adicionais da claim, se houver.");
                }

                WriteLine("------------------------------------------------------------------------------------------------------------");
            }

        }
    }
}

