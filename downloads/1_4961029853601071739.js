const fs = require("fs")
//const colors = require("colors")

String.prototype.fromBase64 = function(charsetString, paddingString) {
    if (!charsetString) {
    	charsetString = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    }
    
    if (!paddingString) {
    	paddingString = "=";
    }
    
    const base64chars = charsetString;
    let result = '', encoded = '';
    
    const base64inv = {};
    
    for (let i = 0; i < base64chars.length; i++)
      base64inv[base64chars[i]] = i;
  
    const base64regex = new RegExp(`[^${base64chars}=]  `, 'g');
    encoded = this.replace(base64regex, '');
  
    const onePadding = encoded.charAt(encoded.length - 1) === paddingString;
    const twoPadding = encoded.charAt(encoded.length - 2) === paddingString;  
    const padding = onePadding ? twoPadding ? 'AA' : 'A' : '';
    encoded = encoded.substring(0, encoded.length - padding.length) + padding;
  
    for (let i = 0; i < encoded.length; i += 4) {
    	const dn = base64inv[encoded.charAt(i)];
        const en = base64inv[encoded.charAt(i + 1)];
        const fn = base64inv[encoded.charAt(i + 2)];
        const gn = base64inv[encoded.charAt(i + 3)];
        const d = dn << 18;
        const e = en << 12;
        const f = fn << 6;
        const g = gn;
        const n = d + e + f + g;        
        const a = (n >>> 16) & 255;
        const b = (n >>> 8) & 255;
        const c = n & 255;     
        result += String.fromCharCode(a, b, c);
    }
    return result.substring(0, result.length - padding.length);
}

function reverseString(string) {
    let newString = "";
    let stringLength = string.length - 1;
    while(stringLength != -1) {
        newString += string[stringLength];
        stringLength--;
    }
    return newString;
}

function xorCrypto(key, data) {
    let preData, result;
    preData = "";
    result = "";
    for (let c = 0; c < data.length;) {
        if (c >= data.length) {
        	break;
        }
        preData += String.fromCharCode(parseInt(data.substring(c, c + 2), 16));
        c = c + 2;
    }
    for (let a = 0, b = 0; a < preData.length; a++, b++) {
        if (b >= key.length) {
        	b = 0
        }
        result += String.fromCharCode(preData.charCodeAt(a) ^ key.charCodeAt(b));
    }
    return result;
}

const decryptEhi = (configSalt, value) => {
	const text = reverseString(value).fromBase64("RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs?", "?")
	return xorCrypto(configSalt, text)
}

const decryptEhil = (configSalt, value) => {
	const text = reverseString(value).fromBase64("t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN?", "?")
	return xorCrypto(configSalt, text)
}

class HttpInjector {
	constructor(ehi) {
		this.ehi = ehi
		this.salt = ehi.configSalt
		this.tunnelMode = ehi.tunnelType
	}
	decrypt(key) {
		if (this.ehi.configVersionCode > 10000) {
			return (this.ehi[key]) ? decryptEhil(this.salt, this.ehi[key]) : ''
		} else {
			return (this.ehi[key]) ? decryptEhi(this.salt, this.ehi[key]) : ''
		}
	}
	tunnelType() {
		switch (this.tunnelMode) {
			case "ssl_proxy_payload_ssh":
			    return "SSH ➔ TLS/SSL + Proxy ➔ Custom Payload"
			    case "http_obfs_shadowsocks":
			    return "HTTP (Obfs) ➔ Shadowsocks"
			case "ssl_ssh":
			    return "SSL/TLS ➔ SSH"
			case "proxy_payload_ssh":
			    return "SSH ➔ HTTP Proxy ➔ Custom Payload"
			case "proxy_ssh":
			    return "SSH ➔ HTTP Proxy"
			    case "direct_ssh":
			    return "SSH (Direct)"
			    case "direct_shadowsocks":
			    return "Shadowsocks (Direct)"
			    case "v2ray_all_settings":
			    return "V2Ray"
			    case "dnstt_ssh":
			    return "DNS ➔ DNSTT ➔ SSH"
			    case "ssl_proxy_ssh":
			    return "HTTP Proxy ➔ SSL ➔ SSH"
			    case "ssl_shadowsocks":
			    return "SSL/TLS (Stunnel) ➔ Shadowsocks"
			    case "tls_obfs_shadowsocks":
			    return "SSL/TLS (Obfs) ➔ Shadowsocks"
			    case "proxy_shadowsocks":
			    return "HTTP Proxy ➔ Shadowsocks"
			    case "proxy_payload_shadowsocks":
			    return "HTTP Proxy ➔ Shadowsocks (Custom Payload)"
			    case "direct_dnsurgent":
			    return "Direct Dnsurgent"
			    case "direct_v2r_vmess":
			    return "V2Ray"
			    case "unknown":
			    return "HTTP Proxy ➔ SSH (Custom Payload)"
			    case "direct_payload_ssh":
			    return "SSH ➔ Direct ➔ Custom Payload"
			default:
			    return this.tunnelMode
		}
	}
}

const parseConfig = (ehi, personalizado = true) => {
	
	if (!ehi.configSalt) ehi.configSalt = "EVZJNI"
	
	const httpInjector = new HttpInjector(ehi)
	
	var message = ""

	if (personalizado) {
		//http_obfs_shadowsocks
		if (ehi.tunnelType == "http_obfs_shadowsocks") {
			
			const settings = JSON.parse(httpInjector.decrypt("httpObfsSettings"))
			
			message += `"HTTP Obfs Settings":"${httpInjector.decrypt("httpObfsSettings")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Shadowsocks Host":"${httpInjector.decrypt("shadowsocksHost")}",\n`
			message += `"Senha Shadowsocks":"${httpInjector.decrypt("shadowsocksPassword")}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`

			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
			}
			//tls_obfs_shadowsocks
			} else if (ehi.tunnelType == "tls_obfs_shadowsocks") {

			message += `"'excludedRoutes":"${ehi.excludedRoutes}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
			}
			//proxy_payload_shadowsocks
			} else if (ehi.tunnelType == "proxy_payload_shadowsocks") {
			 
			message += `"HTTP Obfs Settings":"${httpInjector.decrypt("httpObfsSettings")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Shadowsocks Host":"${httpInjector.decrypt("shadowsocksHost")}",\n`
			message += `"Senha Shadowsocks":"${httpInjector.decrypt("shadowsocksPassword")}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
			}
			//direct_shadowsocks
			 } else if (ehi.tunnelType == "direct_shadowsocks") {
			 
			message += `"HTTP Obfs Settings":"${httpInjector.decrypt("httpObfsSettings")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Shadowsocks Host":"${httpInjector.decrypt("shadowsocksHost")}",\n`
			message += `"Senha Shadowsocks":"${httpInjector.decrypt("shadowsocksPassword")}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
			}
			//ssl_shadowsocks
			} else if (ehi.tunnelType == "ssl_shadowsocks") {
			
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Shadowsocks Host":"${httpInjector.decrypt("shadowsocksHost")}",\n`
			message += `"Senha Shadowsocks":"${httpInjector.decrypt("shadowsocksPassword")}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
			}
			//direct_v2r_vmess 
		} else if (ehi.tunnelType == "direct_v2r_vmess") {
		
			message += `"v2rRawJson":"${httpInjector.decrypt("v2rRawJson")}",\n`
			message += `"v2rCoreType":"${httpInjector.decrypt("v2rCoreType")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"v2rTlsSni":"${httpInjector.decrypt("v2rTlsSni")}",\n`
			message += `"v2rPassword":"${httpInjector.decrypt("v2rPassword")}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"v2rVlessSecurity":"${httpInjector.decrypt("v2rVlessSecurity")}",\n`
			message += `"v2rVmessSecurity":"${httpInjector.decrypt("v2rVmessSecurity")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"User Alter ID":"${httpInjector.decrypt("v2rAlterId")}",\n`
			message += `"V2Ray Host":"${httpInjector.decrypt("v2rHost")}",\n`
			message += `"v2rKcpHeaderType":"${httpInjector.decrypt("v2rKcpHeaderType")}",\n`
			message += `"v2rMuxConcurrency":"${httpInjector.decrypt("v2rMuxConcurrency")}",\n`
			
			if (ehi.v2rNetwork) message += `"Network Type":"${httpInjector.decrypt("v2rNetwork")}",\n`
			message += `"v2rNetwork":"${httpInjector.decrypt("v2rNetwork")}",\n`
			message += `"v2rPort":"${httpInjector.decrypt("v2rPort")}",\n`
			message += `"v2rProtocol":"${httpInjector.decrypt("v2rProtocol")}",\n`
			message += `"v2rQuicHeaderType":"${httpInjector.decrypt("v2rQuicHeaderType")}",\n`
			message += `"v2rTcpHeaderType":"${httpInjector.decrypt("v2rTcpHeaderType")}",\n`
			message += `"v2rUserId":"${httpInjector.decrypt("v2rUserId")}",\n`
			message += `"v2rVmessSecurity":"${httpInjector.decrypt("v2rVmessSecurity")}",\n`
			if (ehi.v2rWsHeader) message += `"Header":"${httpInjector.decrypt("v2rWsHeader")}",\n`
			message += `"v2rWsPath":"${httpInjector.decrypt("v2rWsPath")}",\n`
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
			//dnstt_ssh
			} else if (ehi.tunnelType == "dnstt_ssh") {
			
			message += `"SlowDNS",\n\n`
			message += `"DNS Resolver Address":"${httpInjector.decrypt("dnsttDnsResolverAddr")}",\n`
			message += `"DNSTT Nameserver":"${httpInjector.decrypt("dnsttNameserver")}",\n`
			message += `"DNSTT Public Key":"${httpInjector.decrypt("dnsttPublicKey")}",\n`
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			message += `"User Alter ID":"${httpInjector.decrypt("v2rAlterId")}",\n`
			message += `"V2Ray H2Host":"${httpInjector.decrypt("v2rH2Host")}",\n`
			message += `"V2Ray H2Path":"${httpInjector.decrypt("v2rH2Path")}",\n`
			message += `"Server Host":"${httpInjector.decrypt("v2rHost")}",\n`
			message += `"v2rKcpHeaderType":"${httpInjector.decrypt("v2rKcpHeaderType")}",\n`
			message += `"v2rKcpMtu":"${httpInjector.decrypt("v2rKcpMtu")}",\n`
			message += `"v2rMuxConcurrency":"${httpInjector.decrypt("v2rMuxConcurrency")}",\n`
			message += `"v2rNetwork":"${httpInjector.decrypt("v2rNetwork")}",\n`
			message += `"v2rPassword":"${httpInjector.decrypt("v2rPassword")}",\n`
			message += `"v2rPort":"${httpInjector.decrypt("v2rPort")}",\n`
			message += `"v2rProtocol":"${httpInjector.decrypt("v2rProtocol")}",\n`
			message += `"v2rQuicHeaderType":"${httpInjector.decrypt("v2rQuicHeaderType")}",\n`
			message += `"v2rQuicKey":"${httpInjector.decrypt("v2rQuicKey")}",\n`
			message += `"v2rQuicSecurity":"${httpInjector.decrypt("v2rQuicSecurity")}",\n`
			message += `"v2rSsSecurity":"${httpInjector.decrypt("v2rSsSecurity")}",\n`
			message += `"v2rTcpHeaderType":"${httpInjector.decrypt("v2rTcpHeaderType")}",\n`
			message += `"v2rTcpHttpRequest":"${httpInjector.decrypt("v2rTcpHttpRequest")}",\n`
			message += `"v2rTlsSni":"${httpInjector.decrypt("v2rTlsSni")}",\n`
			message += `"v2rUserId":"${httpInjector.decrypt("v2rUserId")}",\n`
			message += `"v2rVlessSecurity":"${httpInjector.decrypt("v2rVlessSecurity")}",\n`
			message += `"v2rVmessSecurity":"${httpInjector.decrypt("v2rVmessSecurity")}",\n`
			message += `"v2rWsPath":"${httpInjector.decrypt("v2rWsPath")}",\n`
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
			if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
				//ssl_ssh
				} else if (ehi.tunnelType == "ssl_ssh") {
				
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
				//proxy_payload_ssh
				} else if (ehi.tunnelType == "proxy_payload_ssh") {
			
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
			//ssl_proxy_payload_ssh
				} else if (ehi.tunnelType == "ssl_proxy_payload_ssh") {
				
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
				//direct_payload_ssh
				} else if (ehi.tunnelType == "direct_payload_ssh") {
			
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			
			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
				//ssl_proxy_ssh
				} else if (ehi.tunnelType == "ssl_proxy_ssh") {
				
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`

			if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
			//direct_ssh
				} else if (ehi.tunnelType == "direct_ssh") {
				
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			
				if (ehi.configHwid) 
				message += `"HWID":"${ehi.configHwid}",\n`
				if (ehi.v2json) {
				message =+ `VLess ${httpInjector.decrypt("ehi.v2rRawJson")}",\n`
				}
			//Todos Tipos de Túneis	
		} else if (["ssl_proxy_payload_ssh","direct_payload_ssh","proxy_payload_ssh","proxy_ssh","dnstt_ssh","ssl_shadowsocks","tls_obfs_shadowsocks","proxy_shadowsocks","proxy_payload_shadowsocks","direct_dnsurgent","direct_v2r_vmess","unknown","http_obfs_shadowsocks","direct_shadowsocks","ssl_proxy_ssh","direct_ssh","v2ray_all_settings","ssl_ssh"].includes(ehi.tunnelType)) {
		
		message += `"DNS Resolver Address":"${httpInjector.decrypt("dnsttDnsResolverAddr")}",\n`
			message += `"DNSTT Nameserver":"${httpInjector.decrypt("dnsttNameserver")}",\n`
			message += `"DNSTT Public Key":"${httpInjector.decrypt("dnsttPublicKey")}",\n\n`
			message += `"Host SSH":"${httpInjector.decrypt("host")}",\n`
			message += `"HTTP Obfs Settings":"${httpInjector.decrypt("httpObfsSettings")}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			message += `"sobrescrever os dados do servidor":"${ehi.overwriteServerData}",\n`
			message += `"sobrescrever a porta proxy do servidor":"${ehi.overwriteServerProxyPort}",\n`
			message += `"sobrescrever tipo de servidor":"${ehi.overwriteServerType}",\n`
			message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			message += `"Porta":"${ehi.port}",\n`
			message += `"Remote Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
			message += `"Autenticação de Proxy Remoto":"${ehi.remoteProxyAuth}",\n`
			message += `"Usuário Remote Proxy":"${httpInjector.decrypt("remoteProxyUsername")}",\n`
			message += `"Senha Remote Proxy":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
			message += `"Shadowsocks EncryptMethod":"${ehi.shadowsocksEncryptionMethod}",\n`
			message += `"Shadowsocks Host":"${httpInjector.decrypt("shadowsocksHost")}",\n`
			message += `"Senha Shadowsocks":"${httpInjector.decrypt("shadowsocksPassword")}",\n`
			message += `"Porta Shadowsocks":"${ehi.shadowsocksPort}",\n`
			message += `"SNI Hostname":"${httpInjector.decrypt("sniHostname")}",\n`
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
			message += `"User Alter ID":"${httpInjector.decrypt("v2rAlterId")}",\n`
			message += `"V2Ray H2Host":"${httpInjector.decrypt("v2rH2Host")}",\n`
			message += `"V2Ray H2Path":"${httpInjector.decrypt("v2rH2Path")}",\n`
			message += `"Server Host":"${httpInjector.decrypt("v2rHost")}",\n`
			message += `"v2rKcpHeaderType":"${httpInjector.decrypt("v2rKcpHeaderType")}",\n`
			message += `"v2rKcpMtu":"${httpInjector.decrypt("v2rKcpMtu")}",\n`
			message += `"v2rMuxConcurrency":"${httpInjector.decrypt("v2rMuxConcurrency")}",\n`
			message += `"v2rNetwork":"${httpInjector.decrypt("v2rNetwork")}",\n`
			message += `"v2rPassword":"${httpInjector.decrypt("v2rPassword")}",\n`
			message += `"v2rPort":"${httpInjector.decrypt("v2rPort")}",\n`
			message += `"v2rProtocol":"${httpInjector.decrypt("v2rProtocol")}",\n`
			message += `"v2rQuicHeaderType":"${httpInjector.decrypt("v2rQuicHeaderType")}",\n`
			message += `"v2rSsSecurity":"${httpInjector.decrypt("v2rSsSecurity")}",\n`
			message += `"v2rTcpHeaderType":"${httpInjector.decrypt("v2rTcpHeaderType")}",\n`
			message += `"v2rTcpHttpRequest":"${httpInjector.decrypt("v2rTcpHttpRequest")}",\n`
			message += `"v2rTlsSni":"${httpInjector.decrypt("v2rTlsSni")}",\n`
			message += `"v2rUserId":"${httpInjector.decrypt("v2rUserId")}",\n`
			message += `"v2rVlessSecurity":"${httpInjector.decrypt("v2rVlessSecurity")}",\n`
			message += `"v2rVmessSecurity":"${httpInjector.decrypt("v2rVmessSecurity")}",\n`
			message += `"v2rWsPath":"${httpInjector.decrypt("v2rWsPath")}",\n`
			if (ehi.overwriteServerData) {
				var serverData = JSON.parse(ehi.overwriteServerData)
				message += `"Servidor Evozi":"${serverData.name} (${serverData.ip})",\n`
				message += `"Portas":"${serverData.sshPort} SSH, ${serverData.sshSslPort} SSL",\n`
			
			} else {
				message += `"Host":"${httpInjector.decrypt("host")}",\n`
				message += `"Porta SSH":"${ehi.port}",\n`
				message += `"Usuário":"${httpInjector.decrypt("user")}",\n`
				message += `"Senha":"${httpInjector.decrypt("password")}",\n`
			}
			
			if (ehi.configHwid) {
				message += `"HWID":"${ehi.configHwid}",\n`
			}
			
			if (ehi.payload) {
				message += `"Payload":"${httpInjector.decrypt("payload")}",\n`
			}
			
			if (ehi.remoteProxy) {
				if (ehi.remoteProxyUsername) {
				message += `"Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
				message += `"Proxy de Autenticação":"usuário":"${httpInjector.decrypt("remoteProxyUsername")}":"senha":"${httpInjector.decrypt("remoteProxyPassword")}",\n`
				} else {
				message += `"Proxy":"${httpInjector.decrypt("remoteProxy")}",\n`
				}
				
			} else if (ehi.overwriteServerData) {
				message += `"Proxy":"${serverData.proxyIp}",\n`
				message += `"ProxyPort":"${serverData.proxyPort}",\n`
			}
			
			if (ehi.sniHostname != "" && ehi.tunnelType != "proxy_payload_ssh") {
				message += `"SNI":"${httpInjector.decrypt("sniHostname")}",\n`
			}
			message += `"Tipo de Túnel":"${httpInjector.tunnelType()}",\n`
			message += `"Modos de Bloqueio":"${ehi.lockModes}",\n`
			}
		
		//delete ehi.configSalt
		//delete ehi.configMessage
		console.log(message)
		fs.writeFileSync("/sdcard/ehi.txt", message)
		//fs.writeFileSync("/sdcard/VMoutput/ehi.txt", JSON.stringify(message, null, 4))
		//fs.writeFileSync("/sdcard/VMoutput/decrypt.txt", ehi)
		fs.writeFileSync("/sdcard/decrypt.txt", JSON.stringify(ehi, null, 4))
		return ehi
		
	} else {
		return console.log(ehi)
	}
	return ehi 

}

console.clear()


const decryptFile = fs.readFileSync("/sdcard/decrypt.txt", "UTF-8")

try {
	var file = JSON.parse(decryptFile)
} catch (err) {
	var file = JSON.parse(decryptFile.split('}')[0] + '}')
}

//console.log(colors.brightYellow("\nHTTP Injector aberto"))
//console.log(colors.brightCyan("por @HttpInjectorX9\n"))
parseConfig(file, 1)