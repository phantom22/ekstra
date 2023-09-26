function BigIntLog(x, base) {
    let o = 0n;
    for (; base ** o <= x && base ** (o + 1n) <= x; o++)
        ;
    return o;
}
function BigIntAbs(x) {
    return x < 0n ? -1n * x : x;
}
/** A static class that provides a variety of functions to encrypt/decrypt messages.
 *
 * All methods return strings.
 */
class Ekstra {
    static #Enigma = class {
        rotors;
        base;
        constructor(base) {
            this.rotors = [];
            this.base = base;
        }
        getOffset() {
            let o = 0;
            for (let i = 0; i < this.rotors.length; i++)
                o += this.rotors[i];
            this.#rotate();
            return o;
        }
        #rotate() {
            for (let i = 0; i < this.rotors.length; i++) {
                this.rotors[i]++;
                if (i > 0 && this.rotors[i] > (this.base % (i + 3)) * (this.rotors.length - i))
                    this.rotors[i - 1]++;
                while (this.rotors[i] >= this.base)
                    this.rotors[i] -= this.base;
            }
        }
    };
    static hexCharset = "0123456789ABCDEF";
    static base64Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static #charsetIsValid(charset) {
        return charset.length === Array.from(new Set(charset)).length;
    }
    static #charsetContainsString(charset, string) {
        const uniqueChars = Array.from(new Set(string));
        for (let i = 0; i < uniqueChars.length; i++)
            if (!charset.includes(uniqueChars[i]))
                return false;
        return true;
    }
    static #validateInput(msg, key, ch1, ch2, encryption) {
        if (!msg)
            throw "No message to encrypt was provided!";
        else if (encryption && !key)
            throw "No encryption key was provided!";
        else if (!encryption && !key)
            throw "No decryption key was provided!";
        else if (!ch1)
            throw "No base charset was provided!";
        else if (ch1.length < 2)
            throw "The base charset must contain at least two unique symbols!";
        else if (!ch2)
            throw "No target charset was provided!";
        else if (ch2.length < 2)
            throw "The target charset must contain at least two unique symbols!";
        else if (!Ekstra.#charsetContainsString(ch1, msg))
            throw "The provided message contains characters that are not contained in the base charset!";
        else if (encryption && !Ekstra.#charsetContainsString(ch1, key))
            throw "The provided key contains characters that are not contained in the base charset!";
        else if (!encryption && !Ekstra.#charsetContainsString(ch2, key))
            throw "The provided key contains characters that are not contained in the target charset!";
        else if (!Ekstra.#charsetIsValid(ch1))
            throw "The base charset contains duplicates!";
        else if (!Ekstra.#charsetIsValid(ch2))
            throw "The base charset contains duplicates!";
    }
    /**
     * Encrypts a message, given a key and two charsets.
     *
     * ```ch1``` must include all symbols used in both *msg* and *key*.
     * @param {string} msg
     * @param {string} key
     * @param {string} ch1
     * @param {string} ch2
     */
    static encryptWord(msg, key, ch1, ch2) {
        Ekstra.#validateInput(msg, key, ch1, ch2, true);
        const OldBase = BigInt(ch1.length), NewBase = BigInt(ch2.length), enigma = new Ekstra.#Enigma(ch1.length);
        let MsgValue = 0n, KeyValue = 0n, o = "";
        // 1. calculate msg value (most significant symbol to the left)
        for (let i = 0; i < msg.length; i++)
            MsgValue += OldBase ** BigInt(msg.length - 1 - i) * BigInt(ch1.indexOf(msg[i]) + 1); // increment by 1 so that the "zero character" has a non null value
        // 2. calculate the key value and initiate rotors (most significant symbol to the right)
        for (let i = BigInt(key.length - 1); i > -1; i--) {
            const index = ch1.indexOf(key[Number(i)]) + 1; // increment by 1 so that the "zero character" has a non null value
            KeyValue += OldBase ** i * BigInt(index);
            enigma.rotors.push(index);
        }
        let TotalValue = MsgValue * KeyValue;
        // 3. encode the msg while obfuscating it using the rotors logic
        for (let digit = BigIntLog(TotalValue, NewBase); digit > -1; digit--) {
            for (let char = 0n; char < NewBase; char++) {
                const digitValue = NewBase ** digit, // "decimal position" value
                charValue = digitValue * char;
                if (charValue <= TotalValue && charValue + digitValue > TotalValue) {
                    const character = (Number(char) + enigma.getOffset()) % Number(NewBase);
                    TotalValue -= charValue;
                    o += ch2[character];
                }
            }
        }
        return o;
    }
    /**
     * Decrypts a message, given a key and two charsets.
     * @param {string} msg
     * @param {string} key
     * @param {string} ch1
     * @param {string} ch2
     */
    static decryptWord(msg, key, ch1, ch2) {
        Ekstra.#validateInput(msg, key, ch1, ch2, false);
        const OldBase = BigInt(ch1.length), NewBase = BigInt(ch2.length), enigma = new Ekstra.#Enigma(ch2.length);
        let MsgValue = 0n, KeyValue = 0n, o = "";
        // 1. calculate msg value (most significant symbol to the left)
        for (let i = BigInt(key.length - 1); i > -1; i--) {
            const index = ch2.indexOf(key[Number(i)]) + 1; // increment by 1 so that the "zero character" has a non null value
            KeyValue += NewBase ** i * BigInt(index);
            enigma.rotors.push(index);
        }
        // 2. deobfuscate msg by applying inverse rotors logic
        for (let i = 0; i < msg.length; i++) {
            const offset = enigma.getOffset();
            let relativeIndex = BigInt(offset + ch1.indexOf(msg[i]));
            for (let i = 2; i < OldBase; i++)
                relativeIndex -= BigInt(ch1.indexOf(msg[i])) * OldBase - BigInt(offset);
            MsgValue += OldBase ** BigInt(msg.length - 1 - i) * (BigIntAbs(relativeIndex) % OldBase);
        }
        let TotalValue = MsgValue / KeyValue;
        // 3. encode as string the deobfuscated message value
        for (let digit = BigIntLog(TotalValue, NewBase); digit > -1; digit--) {
            for (let char = 0n; char < NewBase; char++) {
                const digitValue = NewBase ** digit, // "decimal position" value
                charValue = digitValue * (char + 1n); // increment by 1 so that the "zero character" has a non null value
                if (charValue <= TotalValue && charValue + digitValue > TotalValue) {
                    TotalValue -= charValue;
                    o += ch2[Number(char)];
                }
            }
        }
        return o;
    }
    /**
     * Returns a safe charset for both the msg and the key.
     * @param {string} msg
     * @param {string} key
     */
    static charsetFromMsgAndKey(msg, key) {
        if (!msg)
            throw "no msg was provided for charset extraction!";
        else if (!key)
            throw "no key was provided for charset extraction!";
        return this.extractAndRandomize(msg + key);
    }
    /**
     * Returns all characters contained in input, without duplicates.
     * @param {string} msg
     * @returns {string}
     */
    static extractCharset(msg) {
        let result = "";
        for (let i = 0; i < msg.length; i++) {
            if (result.includes(msg[i]))
                continue;
            result += msg[i];
        }
        return result;
    }
    /**
     * This function extracts the charset from a given string and shuffles it randomly.
     *
     * @param {string} str
     * @param {number} [maxSubstringLength=0] the length of a single subdivision of the string **msg**.
     */
    static extractAndRandomize(str) {
        let charset = this.extractCharset(str), t = charset, o = "";
        while (o.length !== charset.length) {
            const r = Math.floor(Math.random() * t.length);
            o += t[r];
            t = t.slice(0, r) + t.slice(r + 1);
        }
        return o;
    }
    static randomizeCharset(charset) {
        let t = charset, o = "";
        while (o.length !== charset.length) {
            const r = Math.floor(Math.random() * t.length);
            o += t[r];
            t = t.slice(0, r) + t.slice(r + 1);
        }
        return o;
    }
    static #getSubstrings(fixedSize, msgLength, substringLength) {
        if (!fixedSize && (!substringLength || substringLength < 4 || !Number.isInteger(substringLength)))
            throw "fixeSize must be an integer higher or equal to 3!";
        const o = [];
        for (let i = 0; i < msgLength; i += fixedSize ? substringLength : Math.floor(Math.random() * (substringLength - 3)) + 3)
            o.push(i);
        o.push(msgLength);
        return o;
    }
    static encryptPhrase(msg, key, ch1, ch2, fixedSize, substringLength, inBetween = " ") {
        Ekstra.#validateInput(msg, key, ch1, ch2, true);
        if (typeof fixedSize !== "boolean")
            throw "no fixedSize was provided: cannot interpret whether the substrings should be of fixedSize size or not!";
        else if (!substringLength || typeof substringLength !== "number" || substringLength < 1 || !Number.isInteger(substringLength))
            throw "maxSubstringLength must be a positive integer greater or equal to 1!";
        else if (!Array.isArray(inBetween) && typeof inBetween !== "string")
            throw "inBetween must be either a string or an array of strings!";
        const OldBase = BigInt(ch1.length), NewBase = BigInt(ch2.length), enigma = new Ekstra.#Enigma(ch1.length), cuts = Ekstra.#getSubstrings(fixedSize, msg.length, substringLength);
        let o = "", KeyValue = 0n;
        // 2. calculate the key value and initiate rotors (most significant symbol to the right)
        for (let i = BigInt(key.length - 1); i > -1; i--) {
            const index = ch1.indexOf(key[Number(i)]) + 1; // increment by 1 so that the "zero character" has a non null value
            KeyValue += OldBase ** i * BigInt(index);
            enigma.rotors.push(index);
        }
        for (let i = 0; i < cuts.length - 1; i++) {
            const cut = msg.substring(cuts[i], cuts[i + 1]);
            let MsgValue = 0n;
            // 1. calculate cut value (most significant symbol to the left)
            for (let i = 0; i < cut.length; i++)
                MsgValue += OldBase ** BigInt(cut.length - 1 - i) * BigInt(ch1.indexOf(cut[i]) + 1); // increment by 1 so that the "zero character" has a non null value
            let TotalValue = MsgValue * KeyValue;
            // 3. encode the cut while obfuscating it using the rotors logic
            for (let digit = BigIntLog(TotalValue, NewBase); digit > -1; digit--) {
                for (let char = 0n; char < NewBase; char++) {
                    const digitValue = NewBase ** digit, // "decimal position" value
                    charValue = digitValue * char;
                    if (charValue <= TotalValue && charValue + digitValue > TotalValue) {
                        const character = (Number(char) + enigma.getOffset()) % Number(NewBase);
                        TotalValue -= charValue;
                        o += ch2[character];
                    }
                }
            }
            if (i < cuts.length - 2) {
                if (Array.isArray(inBetween))
                    o += inBetween[i % inBetween.length];
                else
                    o += inBetween;
            }
        }
        return o;
    }
    static decryptPhrase(msg, key, ch1, ch2, inBetween = " ") {
        Ekstra.#validateInput(msg, key, Ekstra.extractCharset(ch1 + (Array.isArray(inBetween) ? inBetween.reduce((a, b) => a + b) : inBetween)), ch2, false);
        if (!Array.isArray(inBetween) && typeof inBetween !== "string")
            throw "inBetween must be either a string or an array of strings!";
        const OldBase = BigInt(ch1.length), NewBase = BigInt(ch2.length), enigma = new Ekstra.#Enigma(ch2.length);
        let cuts = [];
        if (Array.isArray(inBetween)) {
            inBetween = [...new Set(inBetween)];
            for (let i = 0; i < inBetween.length; i++)
                msg = msg.replaceAll(inBetween[i], "\0\0\0");
            cuts = msg.split("\0\0\0");
        }
        else {
            cuts = msg.split(inBetween);
        }
        let o = "", KeyValue = 0n;
        // 1. calculate key value (most significant symbol to the left)
        for (let i = BigInt(key.length - 1); i > -1; i--) {
            const index = ch2.indexOf(key[Number(i)]) + 1; // increment by 1 so that the "zero character" has a non null value
            KeyValue += NewBase ** i * BigInt(index);
            enigma.rotors.push(index);
        }
        for (let i = 0; i < cuts.length; i++) {
            const cut = cuts[i];
            let MsgValue = 0n;
            // 2. deobfuscate cut by applying inverse rotors logic
            for (let i = 0; i < cut.length; i++) {
                const offset = enigma.getOffset();
                let relativeIndex = BigInt(offset + ch1.indexOf(cut[i]));
                for (let i = 2; i < OldBase; i++)
                    relativeIndex -= BigInt(ch1.indexOf(cut[i])) * OldBase - BigInt(offset);
                MsgValue += OldBase ** BigInt(cut.length - 1 - i) * (BigIntAbs(relativeIndex) % OldBase);
            }
            let TotalValue = MsgValue / KeyValue;
            // 3. encode as string the deobfuscated message value
            for (let digit = BigIntLog(TotalValue, NewBase); digit > -1; digit--) {
                for (let char = 0n; char < NewBase; char++) {
                    const digitValue = NewBase ** digit, // "decimal position" value
                    charValue = digitValue * (char + 1n); // increment by 1 so that the "zero character" has a non null value
                    if (charValue <= TotalValue && charValue + digitValue > TotalValue) {
                        TotalValue -= charValue;
                        o += ch2[Number(char)];
                    }
                }
            }
        }
        return o;
    }
    static completeCharset(charset, length = 64) {
        let t = charset.split("");
        const symbols = this.base64Charset.split("");
        do {
            let r = Math.floor(Math.random() * symbols.length);
            let c = symbols.splice(r, 1)[0];
            if (!t.includes(c))
                t.push(c);
        } while (symbols.length > 0 && t.length < length);
        return t.join("");
    }
    static fastEncrypt(msg, fixedSize, substringLength = 0) {
        const ch1 = Ekstra.randomizeCharset(Ekstra.completeCharset(Ekstra.extractCharset(msg), 64)), ch2 = Ekstra.completeCharset(Ekstra.randomizeCharset(Ekstra.hexCharset), 17);
        let key = "";
        for (let i = 0; i < 15; i++)
            key += ch1[Math.floor(Math.random() * ch1.length)];
        const encr = substringLength > 0 ? Ekstra.encryptPhrase(msg, key, ch1, ch2.slice(0, 16), fixedSize, substringLength, ch2[16]) : Ekstra.encryptWord(msg, key, ch1, ch2.slice(0, 16));
        if (Ekstra.decryptPhrase(encr, key, ch2.slice(0, 16), ch1, ch2[16]) !== msg)
            return Ekstra.fastEncrypt(msg, fixedSize, substringLength);
        return substringLength > 0 ? { encr, key, ch1, ch2: ch2.slice(0, 16), inBetween: ch2[16] } : { encr, key, ch1, ch2: ch2.slice(0, 16) };
    }
}
Object.freeze(Ekstra);
