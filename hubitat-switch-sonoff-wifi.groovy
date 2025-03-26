/*
    v2025.0 Victor Tortorello Neto (vtneto@gmail.com)
    
	Based on 2021, version 0.2.0, by Marco Felicio (maffpt@gmail.com).

    Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
    in compliance with the License. You may obtain a copy of the License at:
  
        http://www.apache.org/licenses/LICENSE-2.0
  
    Unless required by applicable law or agreed to in writing, software distributed under the License is distributed
    on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
    for the specific language governing permissions and limitations under the License.
*/

import javax.jmdns.JmDNS
import javax.jmdns.ServiceEvent

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

import groovy.transform.Field
import groovy.json.JsonSlurper

@Field static _namespace = "tortorello.sonoff"

@Field static _driverVersion = "0.2.0"

@Field static _httpRequestPort = "8081"
@Field static _httpRequestTimeout = 5

@Field static _mDNS = null
@Field static _mDNSServiceType = "_ewelink._tcp.local."
@Field static _mDNSServiceListener = null
@Field static _mDNSDiscoveryRunning = false

metadata 
{
    definition (name: "Sonoff Wi-Fi Switch-Man DIY Mode", namespace: _namespace, author: "Victor Tortorello") 
    {
        capability "Switch"        
        command "on"
        command "off"
        command "getInfo"
              
        capability "Initialize"
        command "initialize"
        
        capability "Refresh"
        command "refresh"
        
        attribute "preferencesValidation", "string"
    }

    preferences 
    {
        input ("switchIpAddress",
               "text",
               defaultValue: "",
               required: true,
               submitOnChange: true,
               title: "Sonoff Switch-Man IP Address")
        
        input ("switchDeviceId",
               "text",
               defaultValue: "",
               required: true,
               submitOnChange: true,
               title: "Sonoff Switch-Man Device ID")
        
        input ("switchLanKey",
               "text",
               defaultValue: "",
               required: true,
               submitOnChange: true,
               title: "Sonoff Switch-Man LAN Key")
        
        input ("switchOutlet",
               "number",
               defaultValue: 0,
               required: false,
               submitOnChange: true,
               title: "Sonoff Switch-Man Outlet")
        
        input ("mDNSDiscovery",
               "bool",
               defaultValue: false,
               required: false,
               submitOnChange: true,
               title: "Multicast DNS (mDNS) Discovery")
        
        input ("mDNSDiscoveryInterval",
               "number",
               defaultValue: 15,
               required: false,
               submitOnChange: true,
               title: "Multicast DNS (mDNS) Discovery Interval in Seconds")
        
        input ("debugLogging",
               "bool",
               defaultValue: false,
               required: false,
               submitOnChange: true,
               title: "Enable Debug Logging")
    }
}

def getInfo ()
{
    logDebug "getInfo: IN"
    
    // def deviceData = getDeviceData ()
    
    // initializeDNSDiscovery()
    
    //sendEvent (name: "deviceInformation", value: deviceData)
    
   // if (getDataValue ("switch") != deviceData?.switch) sendEvent (name: "switch", value: deviceData.switch)
                   
    logDebug "getInfo: OUT"
}

def initializeDNSDiscovery()
{
    if (stopDNSDiscovery()) {
        logDebug "Could not initialize; mDNS discovery disabled"
        return
    }
        
    if (_mDNS == null) {
        _mDNS = JmDNS.create("eWeLink")
        
        _mDNSServiceListener = [
            serviceResolved: {}, // { ServiceEvent event -> parseDNSDiscovery(event) },
            serviceRemoved: {}, // { ServiceEvent event -> parseDNSDiscovery(event) },
            serviceAdded: { ServiceEvent event -> parseDNSDiscovery(event) }
        ] as javax.jmdns.ServiceListener
               
        _mDNS.addServiceListener(_mDNSServiceType, _mDNSServiceListener)
        
        logDebug "mDNS initialized now " + _mDNS        
    } else {
    	logDebug "mDNS was already initialized " + _mDNS
    }
    
    //if (!_mDNSDiscoveryRunning) {
    //    schedule("0/${mDNSDiscoveryInterval} 0 0 ? * * *", "runDNSDiscovery")
    //    _mDNSDiscoveryRunning = true
    //}
}

def stopDNSDiscovery() {
    if (mDNSDiscovery) return false
    
    if (_mDNS != null) {
        if (_mDNSServiceListener != null) _mDNS.removeServiceListener(_mDNSServiceType, _mDNSServiceListener)
        
        _mDNS.close()
        _mDNS = null
    }
    
    // _mDNSDiscoveryRunning = false
    // unschedule("runDNSDiscovery")
    
    return true
}
def runDNSDiscovery() {
    if (stopDNSDiscovery()) {
        logDebug "Could not run; mDNS discovery disabled"
        return
    }
    
    logDebug "mDNS discovery started; looping: ${_mDNSDiscoveryRunning}"
    
    // pauseExecution(100)
    
    // _mDNSDiscoveryRunning = true
    // runIn(mDNSDiscoveryInterval, "runDNSDiscovery")
    
    logDebug "mDNS discovery finished; looping: ${_mDNSDiscoveryRunning}"
}

def parseDNSDiscovery(event) {
	def serviceInfo = _mDNS.getServiceInfo(event.getType(), event.getName())

    if (serviceInfo?.getHostAddress()?.equals(switchIpAddress)) {
		logDebug "mDNS service event ${event.getName()} of type ${event.getType()} at address ${serviceInfo.getHostAddress()}"
        
        final deviceId = serviceInfo.getPropertyString("id");
        
        if (!deviceId?.isEmpty()) {
            logDebug "mDNS found device ID ${deviceId}; checking against ${switchDeviceId}"
            
            if (!deviceId.equals(switchDeviceId)) {
            	logDebug "Setting switch device ID to ${deviceId}"
            	device.updateSetting("switchDeviceId", [value: switchDeviceId = deviceId, type: "text"]) // sendEvent(name: "switchDeviceId", value: switchDeviceId = deviceId)
            }
        }

        // for (def a in serviceInfo.getPropertyNames()) logDebug "Service resolved propertyName:" + a + " value:" + serviceInfo.getPropertyString(a)
        
        final data = serviceInfo.getPropertyString("data1");
        final iv = serviceInfo.getPropertyString("iv")
        
        if (data != null && !data.isEmpty() && iv != null && !iv.isEmpty()) {
            def key = generateMD5Hash(switchLanKey)
            def decodedData = data.decodeBase64()
            def decodedIV = iv.decodeBase64()

            def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            def secretKeySpec = new SecretKeySpec(key, "AES")
            def ivParameterSpec = new IvParameterSpec(decodedIV)
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

            def decrypted = new String(cipher.doFinal(decodedData))            
            def decryptedMap = new JsonSlurper().parseText(decrypted)
            
            logDebug "mDNS discovery resolved " + decryptedMap
            
            if (decryptedMap.switches != null) {
                decryptedMap.switches.each { _switch ->
                    if (_switch.outlet == switchOutlet && _switch.switch != null && !_switch.switch.isEmpty()) {
                        logDebug "mDNS updating switch status to ${_switch.switch}"
                        sendEvent(name: "switch", value: _switch.switch)
                    }
                }
            }
        }
    }
}

def installed ()
{
    logDebug "installed: IN"

    initialize()

    logInfo "Sonoff switch DIY mode '${device.label}' installed - don't forget that the device's IP address must be set!"

    logDebug "installed: OUT"
}

def initialize () 
{
    logDebug "initialize: IN"
    logDebug "initialize: device.capabilities = ${device.capabilities}"
    
	initializeDNSDiscovery()
    
    logDebug "initialize: OUT"
}

//
//
//
def refresh ()
{
    logDebug "refresh: IN"
    
    initializeDNSDiscovery()
    getInfo()
    
    logDebug "refresh: OUT"
}

//
//
//
def uninstalled ()
{
    logDebug "uninstalled: IN"
    
	unschedule("runDNSDiscovery")

    logInfo "Sonoff switch DIY mode '${device.label}' successfully uninstalled"
       
    logDebug "uninstalled: OUT"
}


//
//
//
def updated () 
{
    logDebug "updated: IN"
    
    def ipAddressRegex = ~/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/
    def ipAddressOk = ipAddressRegex.matcher(switchIpAddress).matches()
    if (ipAddressOk)
    {
        sendEvent (name: "preferencesValidation", value: "<br />IP address (${switchIpAddress}) is valid")
        logInfo "Device's IP address is valid (${switchIpAddress})"
    }
    else
    {
        sendEvent (name: "preferencesValidation", value: "<br />IP address '${switchIpAddress}' is not valid")
        logInfo "Device's IP address is invalid (${switchIpAddress})"
    }

    initializeDNSDiscovery()
    logDebug "updated: OUT"
}


//
// 
//
def off ()
{
    logDebug "off: IN"

    executeAction ("off")
    
    logDebug "off: OUT"
}


//
// 
//
def on ()
{
    logDebug "on: IN"

    executeAction ("on")

    logDebug "on: OUT"
}

//
// Inner methods
//

//
// Send an action command to the device
//
def executeAction (actionToExecute)
{
    def retrySendingCommand = true
    def retryCount = 0
    def retryLimit = 3
    
    def returnData = [switch: "off"] // "unrecoverable"]
    
    while (retrySendingCommand)
    {
		// --- INÍCIO NETO ---
    
        // Configuração das chaves e IV
        def key = generateMD5Hash(switchLanKey)
        logDebug "executeAction: switchLanKey = ${switchLanKey} generateMD5Hash = ${key}"
        def iv = generateRandomIV(16)

        // def params = ["example": "data"] as Map
        // def params = /{"switches": [{"switch": "off", "outlet": 0}, {"switch": "${actionToExecute}", "outlet": 1}, {"switch": "off", "outlet": 2}, {"switch": "off", "outlet": 3}]}/
        def params = /{"switches":[{"switch":"${actionToExecute}","outlet":${switchOutlet}}]}/

        logDebug "executeAction: params ${params instanceof Map} = ${params}"

        def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        def secretKeySpec = new SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv))

        def encryptedData = cipher.doFinal(params.getBytes("UTF-8"))

        logDebug "executeAction: iv = ${iv} encryptedData = ${encryptedData}"

        def data = [
            data: encryptedData.encodeBase64().toString(),
            deviceid: switchDeviceId,
            encrypt: true,
            iv: iv.encodeBase64().toString(),
            selfApikey: "123",
            sequence: new Date().getTime().toString()
        ]

        logDebug "executeAction: data = ${data}"


        // --- FIM NETO ---

        def uriString = "http://${switchIpAddress}:${_httpRequestPort}/zeroconf/switches"
        Map httpRequest = [uri: uriString, body: /{"data": "${data.data}", "deviceid": "${data.deviceid}", "encrypt": true, "iv": "${data.iv}", "selfApikey": "123", "sequence": "${data.sequence}"}/, contentType: "application/json", requestContentType: "application/json", timeout: _httpRequestTimeout]

        logDebug "executeAction: httpRequest = ${httpRequest}"

        try
        {
            httpPost (httpRequest)
            {
                resp -> 
                    returnData = resp?.data
                
                logDebug "executeAction: returnData = ${returnData}"

                // If we get here, it means that the request went through fine
                // Now let's check if the returned data from the device shows that the command was executed without error
                if (returnData.error != 0)
                {
                    // Nope ... something went wrong
                    // Let's finish here, ok?
                    returnData = [switch: "unknown error (${returnData.error})"]    
                }
                else
                {
                    // Now let's reflect the switch status obtained from the device itself just to be sure and do not reflect a wrong switch event value
                    // NETO returnData = getDeviceData ()
                    returnData = [switch: actionToExecute]
                }
                retrySendingCommand = false
            }
        }
        catch (err)
        {
            logWarn ("executeAction: Error on httpPost = ${err}")
            if (++retryCount >= retryLimit)
            {
                retrySendingCommand = false
                logWarn ("executeAction: Exceeded the maximum number of command sending retries (${retryLimit})")
            }
            else
            {
                // Let's not overhelm the device with requests
                logDebug "executeAction: Pausing for 300 miliseconds ..."
                pauseExecution (300)
            }
        }
        sendEvent (name: "switch", value: returnData.switch)
    }
    
    //if (retryCount < retryLimit)
    //{
    //    getInfo ()
    //}
    
    logDebug "executeAction: OUT"
}

               
//
// Ask the device its data
//
def getDeviceData ()
{
    def retrySendingCommand = true
    def retryCount = 0
    def retryLimit = 3

    //def uriString = "http://${switchIpAddress}:${_httpRequestPort}/zeroconf/info"
    //Map httpRequest = [uri: uriString, body: /{ "data": {}}/, contentType: "application/json", requestContentType: "application/json", timeout: _httpRequestTimeout]
    def returnData = [switch: "off"] //"unrecoverable"]    
    
    //logDebug "executeAction: httpRequest = ${httpRequest}"
    
    while (retrySendingCommand)
    {
        // --- INÍCIO NETO ---
    
        // Configuração das chaves e IV
        def key = generateMD5Hash(switchLanKey)
        logDebug "getDeviceData executeAction: switchLanKey = ${switchLanKey} generateMD5Hash = ${key}"
        def iv = generateRandomIV(16)

        def params = /{}/

        def cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        def secretKeySpec = new SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv))

        def json = [deviceid: "1001ec1db5"]
        def encryptedData = cipher.doFinal(params.getBytes("UTF-8"))

        logDebug "getDeviceData executeAction: iv = ${iv} encryptedData = ${encryptedData}"

        def data = [
            data: encryptedData.encodeBase64().toString(),
            deviceid: json.deviceid,
            encrypt: true,
            iv: iv.encodeBase64().toString(),
            selfApikey: "123",
            sequence: new Date().getTime().toString()
        ]

        logDebug "getDeviceData executeAction: data = ${data}"


        // --- FIM NETO ---

        def uriString = "http://${switchIpAddress}:${_httpRequestPort}/zeroconf/info"
        Map httpRequest = [uri: uriString, body: /{"data": "${data.data}", "deviceid": "${data.deviceid}", "encrypt": true, "iv": "${data.iv}", "selfApikey": "123", "sequence": "${data.sequence}"}/, contentType: "application/json", requestContentType: "application/json", timeout: _httpRequestTimeout]
    	//Map httpRequest = [uri: uriString, body: /{ "data": {}}/, contentType: "application/json", requestContentType: "application/json", timeout: _httpRequestTimeout]

        try
        {
            logDebug "getDeviceData executeAction: httpRequest = ${httpRequest}"
            httpPost (httpRequest)
            {
                resp -> 
                    returnData = resp?.data?.data
                
                logDebug "getDeviceData executeAction: returnData = ${returnData}"
                
                retrySendingCommand = false
            }
        }
        catch (err)
        {
            logWarn ("executeAction: Error on httpPost = ${err}")
            if (++retryCount >= retryLimit)
            {
                retrySendingCommand = false
                logWarn ("executeAction: Exceeded the maximum number of command sending retries (${retryLimit})")
            }
            else
            {
                // Let's not overhelm the device with requests
                logDebug "executeAction: Pausing for 500 miliseconds ..."
                pauseExecution (500)
            }
        }
    }
    
    return returnData
}

def logDebug (message) { if (debugLogging) log.debug (message) }
def logInfo  (message) { log.info (message) }
def logWarn  (message) { log.warn (message) }

def generateMD5Hash(String input) {
    MessageDigest md = MessageDigest.getInstance("MD5")
    return md.digest(input.getBytes("UTF-8"))
}

def generateRandomIV(int length) {
    byte[] iv = new byte[length]
    new Random().nextBytes(iv)
    return iv
}
