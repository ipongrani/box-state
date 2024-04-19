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
import CryptoJS from "crypto-js";


export default function boxState (context) {
    // Function to generate a random string of specified length
    function generateRandomString(length) {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        
        // Generate random bytes
        const randomBytes = CryptoJS.lib.WordArray.random(length);

        // Convert random bytes to a string using the specified character set
        let result = "";
        for (let i = 0; i < length; i++) {
            const index = randomBytes.words[i] % charset.length;
            result += charset.charAt(index);
        }
        return result;
    }
   

    return (() => {
        try {
            // APP STATE
            let appState = {
                states: {},
                actions: {},
            };
            

            if (context) {
                // set context to state
                appState.states = context;
            }

            
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


            function freezeStates() {
               try {
                   
                    // Data to be encrypted
                    const states = getAllStates();

                    // guards
                    const nothingToEncrypted = !states;
                    if (nothingToEncrypted) {
                        throw new Error('Nothing to encrypt.');
                    };

                    // Generate or obtain the secret key
                    const secretKey = generateRandomString(16); // Generate a random string key of length 16

                    // data to encrypt
                    const dataToEncrypt = JSON.stringify(states);
            
                    /// Encrypt and decrypt operations will use the same key
                    const encryptedData = CryptoJS.AES.encrypt(dataToEncrypt, secretKey);

                    // string for storage
                    const encryptedString = encryptedData.toString(); 

                    return { key: secretKey, data: encryptedString };
                } catch (error) {
                    console.error("persistState error:", error);

                    return false;
                }
            }

            function loadFrozenStates({ key, data }) {
                try {
                    // guards
                    const noLoadkey = !key;
                    const noData = !data;
                    if (noLoadkey || noData) {
                        throw new Error('Please provide a key and data.');
                    };

                    // Decrypt the parsed encrypted data
                    const decryptedData = CryptoJS.AES.decrypt(data, key);

                    // Convert the decrypted data to a string
                    const decryptedText = decryptedData.toString(CryptoJS.enc.Utf8);
                    const JsonState = JSON.parse(decryptedText);

                    appState.states = JsonState

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

