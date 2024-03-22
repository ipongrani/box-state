/** @license =============================================================
*
* Copyright (c) 2024 Rani Ipong, https://github.com/ipongrani
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* ========================================================================
*/



export default function boxState (context) {
    // Function to generate a random string of specified length
    function generateRandomString(length) {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let result = "";
        const values = new Uint32Array(length);
        window.crypto.getRandomValues(values);
        for (let i = 0; i < length; i++) {
            result += charset[values[i] % charset.length];
        }
        return result;
    }

   // Function to convert a string key into a CryptoKey object
    async function getKeyFromString(secretKey) {
        try {
            // Convert the string key to an ArrayBuffer
            const keyBuffer = stringToArrayBuffer(secretKey);

            // Import the key from the ArrayBuffer
            const importedKey = await window.crypto.subtle.importKey(
                "raw",
                keyBuffer,
                { name: "AES-GCM" },
                true,
                ["encrypt", "decrypt"]
            );

            return importedKey;
        } catch(err) {
            console.log('error in getKeyFromString: ', err);

            throw new Error(err);
        }
    }

    // Convert a string to an ArrayBuffer
    function stringToArrayBuffer(string) {
        const encoder = new TextEncoder();
        return encoder.encode(string);
    }

    // Convert an ArrayBuffer to a string
    function arrayBufferToString(buffer) {
        const decoder = new TextDecoder();
        return decoder.decode(buffer);
    }

   // Encrypt data
    async function encryptData(data, key) {
        try {
            const encodedData = stringToArrayBuffer(JSON.stringify(data));
            const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization Vector
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                key,
                encodedData
            );

            // Concatenate iv and encryptedData into a single buffer
            let concatenatedBuffer = new Uint8Array(iv.byteLength + encryptedData.byteLength);
            concatenatedBuffer.set(new Uint8Array(iv), 0);
            concatenatedBuffer.set(new Uint8Array(encryptedData), iv.byteLength);

            return concatenatedBuffer.buffer;
        } catch(err) {
            console.log('error in encryptData: ', err);

            throw new Error(err);
        }     
    }

    // Decrypt data
    async function decryptData(encryptedData, key) {
        try {
            // Convert the ArrayBuffer back to Uint8Array
            const concatenatedBuffer = new Uint8Array(encryptedData);

            // Extract iv and encryptedData from concatenated buffer
            const iv = concatenatedBuffer.slice(0, 12);
            const data = concatenatedBuffer.slice(12);

            const decryptedData = await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv,
                },
                key,
                data
            );
            return JSON.parse(arrayBufferToString(decryptedData));
        } catch(err) {
            console.log('error in decryptData: ', err);

            throw new Error(err);
        }
    }

    // Function to convert ArrayBuffer to Base64 string
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    // Function to convert Base64 string to ArrayBuffer
    function base64ToArrayBuffer(base64String) {
        const binaryString = atob(base64String);
        const length = binaryString.length;
        let bytes = new Uint8Array(length);
        for (var i = 0; i < length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    return (() => {
        try {
            // APP STATE
            let appState = {
                states: {},
                actions: {},
            };
            
            // guards
            const noContext = !context;
            const isNotObject = typeof context !== 'object';
            const isEmptyContext = !Object.keys(context).length;
            if (isNotObject || isEmptyContext || noContext) {
                throw new Error('Please provide valid initial values.');
            };

            // set context to state
            appState.states = context;

            
            // functions to exported for user
            function setState(stateName, value) {
                return appState.states[stateName] = value;
            }

            function getState(stateName) {
                return appState.states[stateName];
            }

            function getAllStates() {
                const { states } = appState;
                const isEmpty = !Object.keys(states).length || !states;
                if(isEmpty) {
                    return false;
                }
                return states;
            }


            async function freezeStates() {
               try {
                    // Generate or obtain the secret key
                    const secretKey = generateRandomString(16); // Generate a random string key of length 16

                    // Convert the string key into a CryptoKey object
                    const key = await getKeyFromString(secretKey);

                    // Data to be encrypted
                    const states = getAllStates();

                    // guards
                    const nothingToEncrypted = !states;
                    if (nothingToEncrypted) {
                        throw new Error('Nothing to encrypt.');
                    };

                    // data to encrypt
                    const dataToEncrypt = JSON.stringify(states);
            
                    // Encrypt data
                    const encrypted = await encryptData(dataToEncrypt, key);

                    // string for storage
                    const encryptedString = arrayBufferToBase64(encrypted);


                    return { key: secretKey, data: encryptedString };
                } catch (error) {
                    console.error("persistState error:", error);

                    return false;
                }
            }

            async function loadFrozenStates({ key, data }) {
                try {
                    // guards
                    const noLoadkey = !key;
                    const noData = !data;
                    if (noLoadkey || noData) {
                        throw new Error('Please provide a key and data.');
                    };

                    const encryptKey = await getKeyFromString(key);

                    // buffer for decryption
                    const bufferData = base64ToArrayBuffer(data);

                    // Decrypt data
                    const decrypted = await decryptData(bufferData, encryptKey);

                    // set the state
                    appState.states = JSON.parse(decrypted);

                    return true;
                 } catch (error) {
                     console.error("load states error:", error);

                    return false;
                 }
            }

         

            return {
                getState,
                setState,
                getAllStates,
                freezeStates,
                loadFrozenStates
            };

        
        } catch(err) {
            console.log('error starting boxState app: ', err);
            return false;
        }
    })();
}

(function() {
    if (window && !window.boxState) {
        console.log('Module boxState loaded to window');
        window.boxState = boxState;
    }
})()

