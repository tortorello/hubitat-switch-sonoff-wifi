# Hubitat Switch Sonoff Wi-Fi

Hubitat Elevation driver para o Sonoff Wi-Fi Smart Switch em modo DIY. Este driver permite controlar dispositivos Sonoff diretamente pela plataforma Hubitat, utilizando comunicação local via LAN.

## Funcionalidades

- Controle de dispositivos Sonoff em modo DIY (on/off).
- Descoberta automática de dispositivos via mDNS (Multicast DNS).
- Suporte a múltiplas saídas (outlets) em dispositivos compatíveis.
- Configuração de chaves de criptografia para comunicação segura.
- Logs detalhados para depuração.

## Requisitos

- **Hubitat Elevation**: Certifique-se de que seu hub está configurado e acessível.
- **Dispositivo Sonoff**: O dispositivo deve estar configurado no modo DIY.
- **Rede Local**: O hub e o dispositivo Sonoff devem estar na mesma rede local.

## Instalação

1. **Adicionar o Driver ao Hubitat**:
   - Copie o conteúdo do arquivo `hubitat-switch-sonoff-wifi.groovy`.
   - No Hubitat, vá para a seção **Drivers Code** e clique em **New Driver**.
   - Cole o código e clique em **Save**.

2. **Criar um Dispositivo**:
   - Vá para a seção **Devices** no Hubitat.
   - Clique em **Add Virtual Device**.
   - Escolha o driver `Sonoff Wi-Fi Switch-Man DIY Mode` na lista de drivers.

3. **Configurar o Dispositivo**:
   - Após criar o dispositivo, configure os seguintes campos nas preferências:
     - **Sonoff Switch-Man IP Address**: Endereço IP do dispositivo Sonoff.
     - **Sonoff Switch-Man Device ID**: ID do dispositivo Sonoff.
     - **Sonoff Switch-Man LAN Key**: Chave LAN configurada no dispositivo.
     - **Sonoff Switch-Man Outlet**: Número da saída (se aplicável).
     - **Multicast DNS (mDNS) Discovery**: Ative se desejar descoberta automática.
     - **Debug Logging**: Ative para logs detalhados.

## Uso

- **Ligar e Desligar**: Use os comandos `on` e `off` para controlar o dispositivo.
- **Atualizar Informações**: Use o comando `refresh` para sincronizar o estado do dispositivo.
- **Descoberta mDNS**: Ative a descoberta automática para encontrar dispositivos na rede.

## Logs

O driver fornece três níveis de logs:
- **Debug**: Logs detalhados para depuração (ativado nas preferências).
- **Info**: Informações gerais sobre o funcionamento.
- **Warn**: Avisos em caso de erros ou problemas.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests.

## Licença

Este projeto está licenciado sob a [Apache License 2.0](LICENSE).

## Contato

- **Autor Original**: Marco Felicio (maffpt@gmail.com)
- **Atualizações**: Victor Tortorello Neto (vtneto@gmail.com)
