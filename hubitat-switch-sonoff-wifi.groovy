/*
    v0.2.2 Victor Tortorello Neto (vtneto@gmail.com)
    
	Based on 2021, version 0.2.0 by Marco Felicio (maffpt@gmail.com).

    Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
    in compliance with the License. You may obtain a copy of the License at:
  
        http://www.apache.org/licenses/LICENSE-2.0
  
    Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
    on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
    for the specific language governing permissions and limitations under the License.
*/

import java.time.Instant
import java.time.Duration

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

import groovy.transform.Field
import groovy.json.JsonSlurper

@Field static final _namespace = "tortorello.sonoff"

@Field static final _driverVersion = "0.2.2"

@Field static final _httpRequestPort = "8081"
@Field static final _httpRequestTimeout = 5

@Field static final _mDNSHost = "224.0.0.251"
@Field static final _mDNSPort = 5353
@Field static final _mDNSServiceType = "_ewelink._tcp.local."

metadata {
    definition(name: "Sonoff Wi-Fi Switch DIY", namespace: _namespace, author: "Victor Tortorello", singleThreaded: true) {
        capability "Switch"        
        command "on"
        command "off"
              
        capability "Initialize"
        command "initialize"
        
        capability "Refresh"
        command "refresh"
        
        attribute "preferencesValidation", "string"
    }

    preferences {
        input("switchIpAddress",
              "text",
              defaultValue: "",
              required: true,
              submitOnChange: true,
              title: "Sonoff Switch IP Address")
        
        input("switchDeviceId",
              "text",
              defaultValue: "",
              required: true,
              submitOnChange: true,
              title: "Sonoff Switch Device ID")
        
        input("switchLanKey",
              "text",
              defaultValue: "",
              required: true,
              submitOnChange: true,
              title: "Sonoff Switch Device API Key")
        
        input("switchOutlet",
              "number",
              defaultValue: 0,
              required: false,
              submitOnChange: true,
              title: "Sonoff Switch Outlet")
        
        input("mDNSDiscovery",
              "bool",
              defaultValue: false,
              required: false,
              submitOnChange: true,
              title: "Multicast DNS (mDNS) Discovery")
                
        input("debugLogging",
              "bool",
              defaultValue: false,
              required: false,
              submitOnChange: true,
              title: "Enable Debug Logging")
    }
}
                                     
def installed () {
    logDebug "Installing device..."

    initialize()

    logInfo "Sonoff Wi-Fi Switch DIY '${device.label}' installed. Don't forget that the device's IP address, ID, LAN key and outlet must be set."
}

def initialize() {
    logDebug "Initializing device..."
    logDebug "Device capabilities: ${device.capabilities}"
    
    initializeDNSDiscovery(true)
}

def refresh() {
    logDebug "Refreshing device..."
    
    initializeDNSDiscovery(true)
}

def uninstalled() {
    logDebug "Uninstalling device..."
    
    stopDNSDiscovery(true)
    
    logInfo "Device '${device.label}' successfully uninstalled."
}

def updated() {
    logDebug "Updating device..."
    
    def ipAddressRegex = ~/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/
    def ipAddressOk = ipAddressRegex.matcher(switchIpAddress).matches()
    
    if (ipAddressOk) {
        sendEvent (name: "preferencesValidation", value: "<br />IP address (${switchIpAddress}) is valid")
        logInfo "Device's IP address is valid (${switchIpAddress})"
    } else {
        sendEvent (name: "preferencesValidation", value: "<br />IP address '${switchIpAddress}' is not valid")
        logInfo "Device's IP address is invalid (${switchIpAddress})"
    }

    initializeDNSDiscovery(true)
}

def off() {
    executeAction("off")
}

def on() {
    executeAction("on")
}

//
// Inner methods
//

void parse(message) {
    final messageObj = new JsonSlurper().parseText(message);
       
    if (!messageObj?.fromIp?.equals(switchIpAddress)) {
        logDebug "mDNS message from IP ${messageObj?.fromIp} dropped; expected ${switchIpAddress}"
        return
    }
    
    byte[] payload = hubitat.helper.HexUtils.hexStringToByteArray(messageObj.payload) 
    def payloadStr = new String(payload, "ISO-8859-1")
    
    def payloadKeyVal = extractKeyValuePairs(payloadStr)
    
    logDebug "Decoded mDNS message: $payloadKeyVal"
    
    parseDNSDiscovery(["fromIp": messageObj.fromIp] + payloadKeyVal)
}

def initializeDNSDiscovery(forceStop = false)
{
    logDebug "Initializing mDNS socket..."
    
    if (stopDNSDiscovery(forceStop) && !mDNSDiscovery) {
        logDebug "Could not initialize; mDNS discovery disabled"
        return
    }

    def socket = interfaces.getMulticastSocket(_mDNSHost, _mDNSPort)
    
    logDebug "Connecting mDNS socket..."
    
    if (!socket.connected) socket.connect()
}

def stopDNSDiscovery(forceStop = false) {
    logDebug "Stopping mDNS socket" + (forceStop ? " FORCED" : "") + "..."
    
    if (mDNSDiscovery && !forceStop) return false

    def socket = interfaces.getMulticastSocket(_mDNSHost, _mDNSPort)
    if (socket.connected) socket.disconnect()
    
    return true
}

def parseDNSDiscovery(payload) {
    logDebug "Parsing mDNS discovery..."
    
    if (!payload?.data1 || !payload?.iv) {
        logDebug "Lack of data and IV fields in the mDNS message; not parsed"
        return
    }
    
    if (!payload?.fromIp?.equals(switchIpAddress)) {
        logDebug "mDNS on different IP ${payload?.fromIp}; not parsed"
        return
    }
   
    /*
	final deviceId = serviceInfo.getPropertyString("id");

    if (!deviceId?.isEmpty()) {
        logDebug "mDNS found device ID ${deviceId}; checking against ${switchDeviceId}"

        if (!deviceId.equals(switchDeviceId)) {
            logDebug "Setting switch device ID to ${deviceId}"
            device.updateSetting("switchDeviceId", [value: switchDeviceId = deviceId, type: "text"])
        }
    }
    */
        
    final decrypted = decryptData(payload.data1, payload.iv); 

    logDebug "mDNS discovery resolved " + decrypted
    
    def newSwitchVal = null

    if (decrypted.switches != null) { // Switch-Man
        decrypted.switches.each { _switch ->
            if (_switch.outlet == switchOutlet && !!_switch.switch) newSwitchVal = _switch.switch
        }
    } else if (!!decrypted.switch) { // Basic
        newSwitchVal = decrypted.switch
    }
    
    if (newSwitchVal) {
        logDebug "mDNS updating switch status to ${newSwitchVal}"
        sendEvent(name: "switch", value: newSwitchVal)
    }
}

def executeAction(actionToExecute) {
    def retrySendingCommand = true
    def retryCount = 0
    def retryLimit = 3
    
    def returnData = [switch: "off"]
    
    while (retrySendingCommand) {
        def data = null
        
        if (switchOutlet < 0) data = /{"switch":"${actionToExecute}"}/
        else data = /{"switches":[{"switch":"${actionToExecute}","outlet":${switchOutlet}}]}/

        def iv = generateRandomIV(16)
        def encrypted = encryptData(data, iv)

        def body = [
            data: encrypted.encodeBase64().toString(),
            deviceid: switchDeviceId,
            encrypt: true,
            iv: iv.encodeBase64().toString(),
            selfApikey: "123",
            sequence: new Date().getTime().toString()
        ]

        logDebug "Executing action... $body"

        def uriString = "http://${switchIpAddress}:${_httpRequestPort}/zeroconf"
        
        if (switchOutlet < 0) uriString += "/switch"
        else uriString += "/switches"
        
        Map httpRequest = [
            uri: uriString,
            body: /{"data": "${body.data}", "deviceid": "${body.deviceid}", "encrypt": true, "iv": "${body.iv}", "selfApikey": "123", "sequence": "${body.sequence}"}/,
            contentType: "application/json",
            requestContentType: "application/json",
            timeout: _httpRequestTimeout]

        logDebug "Sending HTTP request..."

        try {
            httpPost(httpRequest) {
                resp -> returnData = resp?.data
                
                logDebug "HTTP response: ${returnData}"

                // If we get here, it means that the request went through fine
                // Now let's check if the returned data from the device shows that the command was executed without error
                if (returnData.error != 0) {
                    // Nope ... something went wrong
                    // Let's finish here, ok?
                    returnData = [switch: "unknown error (${returnData.error})"]    
                } else {
                    // Now let's reflect the switch status obtained from the device itself just to be sure and do not reflect a wrong switch event value
                    returnData = [switch: actionToExecute]
                    sendEvent(name: "switch", value: actionToExecute)
                }
                
                retrySendingCommand = false
            }
        } catch (err) {
            logWarn "Error on HTTP request: $err"
            
            if (++retryCount >= retryLimit) {
                retrySendingCommand = false
                logWarn "Exceeded the maximum number of command sending HTTP request retries ($retryLimit)"
            } else {
                // Let's not overhelm the device with requests
                logDebug "Pausing for 300 ms..."
                pauseExecution(300)
            }
        }
    }
}

def encryptData(String data, byte[] iv) {
	def key = generateMD5Hash(switchLanKey)
    
    final cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    final keySpec = new SecretKeySpec(key, "AES")
    final ivSpec = new IvParameterSpec(iv)
    
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)

    return cipher.doFinal(data.getBytes("UTF-8"))
}

def decryptData(String encodedData, String encodedIV) {
	def key = generateMD5Hash(switchLanKey)
    
    def data = encodedData.decodeBase64()
    def iv = encodedIV.decodeBase64()    
    
    final cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    final keySpec = new SecretKeySpec(key, "AES")
    final ivSpec = new IvParameterSpec(iv)
    
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
    
    def decryptedData = new String(cipher.doFinal(data), "UTF-8")
    
    return new JsonSlurper().parseText(decryptedData)
}

def generateMD5Hash(String input) {
    MessageDigest md = MessageDigest.getInstance("MD5")
    return md.digest(input.getBytes("UTF-8"))
}

def generateRandomIV(int length) {
    byte[] iv = new byte[length]
    new Random().nextBytes(iv)
    return iv
}

Map<String, String> extractKeyValuePairs(String message, CharSequence splitBy = '[\\x00\\s\\p{Cntrl}\\u0080-\\uFFFF]+') {
    def result = [:]
    def parts = message.split(splitBy)

    parts.each { part ->
        if (part.contains("=")) {
            def (k, v) = part.split("=", 2)
            result[k.trim()] = v.trim()
        }
    }

    return result
}

def logDebug (message) { if (debugLogging) log.debug (message) }
def logInfo  (message) { log.info (message) }
def logWarn  (message) { log.warn (message) }
