let DECR_CUTS = [] as bigint[],
    ENCR_CUTS = [] as bigint[];

function BigIntLog(x:bigint,base:bigint) {
    if (base < 37) return BigInt(x.toString(Number(base)).length - 1);
    let o = BigInt(Math.trunc(x.toString().length / Math.log10(Number(base))) - 1);
    for (let t=base**o; t <= x && t*base <= x; o++,t=base**o);
    return o;
}
function _BigIntParseNext(x:bigint,base:bigint,power=BigIntLog(x,base)-1n): [char:bigint,charValue:bigint] {
    if (x < base)
        return [x,x];

    const magnitude = base ** power;
    //console.log(magnitude);

    if (magnitude > x)
        return [0n,0n];

    let l=0n, r=base, char = r / 2n;
    // [1,2,3,4]

    const maxIter = Math.ceil(Math.log2(Number(base))) + 1;
    let currIter = 0;
    
    while (true) {
        currIter++;
        //console.log({char,l,r});
        const charValue = char*magnitude,
              test = charValue <= x;

        if (currIter === maxIter || test && charValue + magnitude >= x) {
            return [char,charValue];
        }
        
        if (test) {
            l = char;
            char = (char + r + 1n) / 2n;
        }
        else {
            r = char;
            char = (l + char + 1n) / 2n;
        }
    }
}

function BigIntParseNext(x:bigint,base:bigint,power=BigIntLog(x,base)-1n): [char:number,charValue:bigint] {
    if (x < base)
        return [Number(x),x];

    const magnitude = base ** power,
          char = x / magnitude,
          charValue = char * magnitude;

    return [Number(char),charValue]
}

function BigIntAbs(x:bigint) {
    return x<0n ? -x : x
}
function BigIntGCD(a:bigint,b:bigint) {
    let temp:bigint;
    while (b !== 0n) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}   
function BigIntArrMin(arr:bigint[]) {
	let min = arr[0];
	for (let i=1; i<arr.length; i++) {
		if (arr[i] < min)
			min = arr[i];
	}
	return min;
}
function BigIntArrMax(arr:bigint[]) {
	let max = arr[0];
	for (let i=1; i<arr.length; i++) {
		if (arr[i] > max)
			max = arr[i];
	}
	return max;
}
function BigIntMax(a:bigint,b:bigint) {
    return a>b ? a : b;
}
function BigIntMin(a:bigint,b:bigint) {
    return a<b ? a : b;
}

/** A static class that provides a variety of functions to encrypt/decrypt messages.
 * 
 * All methods return strings.
 */
class Ekstra {
    constructor() {
        throw "Illegal constructor.";
    }

    static Xorshift = function *(seed: bigint): Generator<number, number, void> {
        let x = Number(seed & 0xFFFFFFFFn);
        
        while (true) {
            x ^= (x << 13) & 0xFFFFFFFF;
            x ^= (x >>> 17);
            x ^= (x << 5) & 0xFFFFFFFF;
            x = x >>> 0;
        
            yield x & 0xFFFF;
        }
    }

    static Enigma = function *(seed:string, baseCharset:string): Generator<number, number, void> {
        const l = seed.length,
              l_1 = l-1;

        let max = 1;

        function adjustRotors(i:number) {
            let v = rotors[i];

            while (v > 106) {
                const rotations = Math.trunc(0.009345794392523365*v); // v/107
                v = v - 107*rotations + 1; // v = v % 107 + 1
                rotors[i] = v;
    
                if (v > max)
                    max = v;

                if (i < l_1) {
                    i++;
                    rotors[i] += rotations;
                    v = rotors[i];
                }
            }

            if (v > max)
                max = v;
        }
    
        function rotate() {
            sum = 1;

            const all = Math.trunc(max / l),
                  some = max - all * l;

            max = 1;
            for (let i=0, j = some; i<l; i++, j--) {
                rotors[i] += all;
                if (j > 0n)
                    rotors[i]++;
                sum += pre[i] * rotors[i];
                adjustRotors(i);
            }
        }
        
        const rotors = new Array(l) as number[],
              pre = new Array(l) as number[];

        let sum = 1;
        for (let i=l_1, p=i+4; i > -1; i--, p=i+4) {
            rotors[i] = 3*(baseCharset.indexOf(seed[i]) + 1) ** 3;
            sum += p * rotors[i];
            pre[i] = p;
            adjustRotors(i); 
        }

        while (true) {
            yield (1647030*(sum % 5468752394) + 1) % 2147483648;
            rotate();
        }
    };
    static hex = "0123456789ABCDEF";
    static base10 = "0123456789";
    static base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static base97 = " \n\tABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    static base128 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁ" 
    static base256 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁ";
    static base512 = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŉŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſƀƁƂƃƄƅƆƇƈƉƊƋƌƍƎƏƐƑƒƓƔƕƖƗƘƙƚƛƜƝƞƟƠơƢƣƤƥƦƧƨƩƪƫƬƭƮƯưƱƲƳƴƵƶƷƸƹƺƻƼƽƾƿǀǁǂǃǄǅǆǇǈǉǊǋǌǍǎǏǐǑǒǓǔǕǖǗǘǙǚǛǜǝǞǟǠǡǢǣǤǥǦǧǨǩǪǫǬǭǮǯǰǱǲǳǴǵǶǷǸǹǺǻǼǽǾǿȀȁȂȃȄȅȆȇȈȉȊȋȌȍȎȏȐȑȒȓȔȕȖȗȘșȚțȜȝȞȟȠȡȢȣȤȥȦȧȨȩȪȫȬȭȮȯȰȱȲȳȴȵȶȷȸȹȺȻȼȽȾȿɀɁ";
    static unicode = (function(){ let o=""; for (let i=0; i<2**16; i++) o+=String.fromCharCode(i); return Array.from(new Set(o)).join(""); })();

    //static #charsetIsValid(charset:string) {
    //    return charset.length === Array.from(new Set(charset)).length
    //}

    static #charsetContainsString(charset:string,string:string) {
        // console.log(`charsetContainsString(\n    charset:='${charset}'\n    string:='${string}'\n)`)
        const uniqueChars = Array.from(new Set(string));
        for (let i=0; i<uniqueChars.length; i++)
            if (!charset.includes(uniqueChars[i])) return false;
        return true
    }

    static #validateInput(msg:string,key:string,ch1:string,ch2:string,encryption:boolean) {
        if (!msg) throw "No message to encrypt was provided!";
        else if (encryption&&!key) throw "No encryption key was provided!";
        else if (!encryption&&!key) throw "No decryption key was provided!";
        else if (!ch1) throw "No base charset was provided!";
        else if (ch1.length < 2) throw "The base charset must contain at least two unique symbols!";
        else if (!ch2) throw "No target charset was provided!";
        else if (ch2.length < 2) throw "The target charset must contain at least two unique symbols!";
        else if (!Ekstra.#charsetContainsString(ch1,msg)) throw "The provided message contains characters that are not contained in the base charset!";
        else if (encryption&&!Ekstra.#charsetContainsString(ch1,key)) throw "The provided key contains characters that are not contained in the base charset!";
        // else if (!encryption&&!Ekstra.#charsetContainsString(ch2,key)) throw "The provided key contains characters that are not contained in the target charset!";
        //else if (!Ekstra.#charsetIsValid(ch1)) throw "The base charset contains duplicates!";
        //else if (!Ekstra.#charsetIsValid(ch2)) throw "The base charset contains duplicates!";
    }
    static keyValue(key:string,ch:string): bigint {
        const base = BigInt(ch.length);
        let value = 0n;
        for (let i = BigInt(key.length - 1); i > -1; i--)
            value += base ** i * BigInt(ch.indexOf(key[Number(i)]) + 1);
        return value;
    }
    static msgValue(msg:string,ch:string): bigint {
        const base = BigInt(ch.length);
        let value = 0n;
        for (let i=0; i<msg.length; i++)
            value += base ** BigInt(msg.length - 1 - i) * BigInt(ch.indexOf(msg[i]) + 1);
        return value;
    }
    static msgValueFromDict(msg:string,base_length:number,dictionary_ch:{[char:string]:number}): bigint {
        const base = BigInt(base_length);
        let value = 0n;
        for (let i=0; i<msg.length; i++)
            value += base ** BigInt(msg.length - 1 - i) * BigInt(dictionary_ch[msg[i]] + 1);
        return value;
    }
    static msgParameterFromDict(msg:string,base_length:number,dictionary_ch:{[char:string]:number}): number {
        let tmp = 0;
        for (let j=2; j < base_length && j < msg.length; j++) {
            //console.log(cut[j]);
            tmp += dictionary_ch[msg[j]];
        }
        return tmp;
    }
    /**
     * Returns a safe charset for both the msg and the key.
     * @param {string} msg
     * @param {string} key
     */
    static charsetFromMsgAndKey(msg: string, key: string) {
        if (!msg) throw "no msg was provided for charset extraction!";
        else if (!key)  throw "no key was provided for charset extraction!";
        return this.extractAndRandomize(msg+key);
    }
    /**
     * Returns all characters contained in input, without duplicates.
     * @param {string} msg
     * @returns {string}
     */
    static extractCharset(msg: string) {
        let result = "";
        for (let i=0; i<msg.length; i++) {
            if (result.includes(msg[i])) continue;
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
    static extractAndRandomize(str: string) {
        return Ekstra.shuffleString(this.extractCharset(str));
    }
    static shuffleString(charset:string) {
        let arr = charset.split('');

        // Fisher-Yates shuffle
        for (let i=arr.length-1, t=arr[i], j:number; i>0; i--,t=arr[i]) {
            j = Math.floor(Math.random() * (i + 1));
            arr[i] = arr[j];
            arr[j] = t;
            // [arr[i], arr[j]] = [arr[j], arr[i]];
        }

        return arr.join('');
    }
    static invertString(msg:string) {
        let m = Array.from(msg);
        for (let i=0,tmp=m[i],j=msg.length-1; i<Math.ceil(msg.length/2); i++,tmp=m[i],j=msg.length-1-i) {
            m[i] = m[j];
            m[j] = tmp;
        }
        return m.join("");
    }
    static scrambleMsg(msg:string,seed:bigint) {
        const gen = Ekstra.Xorshift(seed),
              a = msg.split(""),
              l = a.length;
        for (let i=0,t=a[i],j=gen.next().value%l; i<l; i++,t=a[i],j=gen.next().value%l) {
            a[i] = a[j];
            a[j] = t;
        }
        gen.return(0);
        return a.join("");
    }
    static unscrambleMsg(msg:string,seed:bigint) {
        const gen = Ekstra.Xorshift(seed),
              a = msg.split(""),
              l = a.length;
    
        const v = Array(l).fill(0) as number[];
        for (let i=0; i<l; i++)
            v[i] = gen.next().value;
        gen.return(0);
        for (let i=l-1,j=v[i]%l,t=a[i]; i>-1; i--,t=a[i],j=v[i]%l) {
            a[i] = a[j];
            a[j] = t;
        }
        return a.join("");
    }
    static encrypt(msg:string, key:string, ch1:string, ch2:string, substringLength=msg.length, inBetween=" ", padSymbol="", verbose=false) {
        Ekstra.#validateInput(msg,key,ch1,ch2,true);
        if (!substringLength || typeof substringLength !== "number" || substringLength<1 || !Number.isInteger(substringLength))
            throw "maxSubstringLength must be a positive integer greater or equal to 1!";
        else if (typeof inBetween!=="string")
            throw "inBetween must be a string!";

        msg = Ekstra.padMsg(msg, substringLength, padSymbol);
        //msg = Ekstra.scrambleMsg(msg);

        const NewBaseN = ch2.length,
              NewBase = BigInt(NewBaseN),
              enigma = Ekstra.Enigma(key, ch1);

        let o = "",
            KeyValue = Ekstra.keyValue(key, ch1),
            cuts = Math.ceil(msg.length / substringLength),
            dictionary_ch1 = Ekstra.#getDictionary(ch1);

        msg = Ekstra.scrambleMsg(msg,KeyValue);

        ENCR_CUTS = [];

        for (let k=0,l=0; k<cuts; k++,l+=substringLength) {

            const cut = msg.slice(l,l+substringLength),
                  MsgValue = Ekstra.msgValueFromDict(cut, ch1.length, dictionary_ch1);

            ENCR_CUTS.push(MsgValue);

            let TotalValue = MsgValue * KeyValue,
                encr_cut = "";

            // encode the cut while obfuscating it using the rotors logic
            for (let digit=BigIntLog(TotalValue,NewBase); digit > -1n; digit--) {
                const n = BigIntParseNext(TotalValue,NewBase,digit),
                      character = (n[0] + enigma.next().value) % NewBaseN;
                TotalValue -= n[1];
                encr_cut += ch2[character];
            }

            o += encr_cut;

            if (k < cuts-1)
                o += inBetween;

            if (verbose) console.log(`encrypted ${k+1}/${cuts} segments: '${cut}' => '${encr_cut}'.`);
        }

        // close the generator
        enigma.return(0);

        return o;
    }
    static #getDictionary(ch:string) {
        let o: { [char:string]: number } = {};
        for (let i=0; i<ch.length; i++)
            o[ch[i]] = i;
        return o;
    }
    // { ch1:42, ch2:256, keyLength:4, substringLength:512, padSymbol:"", inBetween:"", verbose:false }
    static decrypt(msg:string, key:string, ch1:string, ch2:string, inBetween:string=" ", padSymbol="", verbose=false) {
        Ekstra.#validateInput(msg,key,Ekstra.extractCharset(ch1+inBetween),ch2,false);
        if (typeof inBetween !== "undefined" && typeof inBetween!=="string")
            throw "the inBetween parameter, if passed, must be either a string!";

        const OldBaseN = ch1.length,
              OldBase = BigInt(OldBaseN),
              NewBase = BigInt(ch2.length),
              enigma = Ekstra.Enigma(key, ch2);
              
        let cuts = typeof inBetween === "undefined" ? [msg] : msg.split(inBetween);

        let o = "",
            KeyValue = Ekstra.keyValue(key, ch2);

        const dictionary_ch1 = Ekstra.#getDictionary(ch1);
        
        DECR_CUTS = [];

        for (let i=0; i<cuts.length; i++) {
            const cut = cuts[i];
            let TotalValue = 0n;
            
            const msgParameter = Ekstra.msgParameterFromDict(cut, ch1.length, dictionary_ch1);

            // 1. deobfuscate cut by applying inverse rotors logic
            for (let j=0; j<cut.length; j++) {
                const x = enigma.next().value,
                      relativeIndex = Math.abs(x - msgParameter) * OldBaseN - x + dictionary_ch1[cut[j]],
                      charValue = OldBase ** BigInt(cut.length - 1 - j) * BigInt(relativeIndex % OldBaseN);

                //if (i === 7) {
                //    console.log({x,relativeIndex,charValue,firstTerm:BigIntAbs(x - msgParameter),secondTerm:x,thirdTerm:BigInt(dictionary_ch1[cut[i]])})
                //}
                TotalValue += charValue;
            }

            let MsgValue = TotalValue / KeyValue,
                decr_cut = "";

            DECR_CUTS.push(MsgValue);

            // 2. encode as string the deobfuscated message value
            while (MsgValue > 0n) {
                let index = (MsgValue % NewBase) - 1n;
                if (index < 0n) index += NewBase;
        
                decr_cut = ch2[Number(index)] + decr_cut;
        
                MsgValue = (MsgValue - (index + 1n)) / NewBase;
            }

            o += decr_cut;

            if (verbose) console.log(`decrypted ${i+1}/${cuts.length} segments: '${cut}' => '${decr_cut}'.`);
        }

        // close the generator
        enigma.return(0);

        o = Ekstra.unscrambleMsg(o,KeyValue);
        o = Ekstra.removePadding(o, padSymbol);

        return o;
    }
    static completeCharset(charset:string,length=64) {
        if (charset.length >= length)
            return charset;
        let t = charset.split("");
        const symbols = (Ekstra.base512).split("");
        do {
            let r = Math.floor(Math.random() * symbols.length);
            let c = symbols.splice(r,1)[0];
            if (!t.includes(c)) t.push(c);
        }
        while (symbols.length>0&&t.length<length);
        return t.join("")
    }
    static randomKey(ch:string,keyLength:number):string {
        let key:string;
        do {
            key = "";
            for (let i=0; i<keyLength; i++)
                key += ch[Math.floor(Math.random() * ch.length)];
        }
        while (BigIntGCD(Ekstra.keyValue(key, ch), BigInt(ch.length)) !== 1n);
        return key;
    }
    static padMsg(msg:string,substringLength:number,padSymbol:string) {
        if (substringLength < 2 || padSymbol === "" || msg.length % substringLength === 0)
            return msg;
        const length = msg.length;
        return msg + padSymbol.repeat(substringLength - length % substringLength);
    }
    /** Output size is approx. 2 times bigger than the input msg. */
    static secureArgs(verbose=false) {
        return {ch2:256,keyLength:256,substringLength:256,padSymbol:" ",inBetween:"",verbose}
    }
    /** Output size is approx. 6.874% (6.648% without padding) bigger than the input msg. */
    static compactArgs(verbose=false) {
        return {ch2:256,keyLength:16,substringLength:256,padSymbol:" ",inBetween:"",verbose}
    }
    /** Output size is approx. 3.742% (3.516% without padding)  bigger than the input msg. */
    static superCompactArgs(verbose=false) {
        return {ch2:256,keyLength:8,substringLength:256,padSymbol:" ",inBetween:"",verbose}
    }
    /** Output size is approx. 0.71% (0.481% without padding)  bigger than the input msg. */
    static ultraCompactArgs(verbose=false) {
        return {ch2:256,keyLength:4,substringLength:1024,padSymbol:" ",inBetween:"",verbose}
    }
    static fastArgs(verbose=false) {
        return {keyLength:16,substringLength:16,padSymbol:" ",inBetween:"",verbose}
    }
    static shortMsg(verbose=false) {
        return {ch1:64,ch2:511,keyLength:8,substringLength:1};
    }
    static removePadding(string:string,padSymbol:string) {
        if (padSymbol === "") return string;
        let i = string.length;
        for (; i>-1; i--) {
            if (string[i-1] === padSymbol) continue;
            else break;
        }
        return string.slice(0,i)
    }
    static randomCharset(length:number,inBetween=" ") {
        let o = "", t=Ekstra.base512.split("");

        if (inBetween !== "") {
            const _i = t.indexOf(inBetween);
            if (_i !== -1) {
                t.splice(_i,1);
            }
        }

        for (let i=0; i<length && t.length>0; i++) {
            const j = Math.floor(Math.random() * t.length);
            o += t[j];
            t.splice(j,1);
        }
        return o;
    }
    static fastEncrypt(msg:string,{ch1=256,ch2=17,keyLength=15,substringLength=msg.length,padSymbol="",inBetween=" ",verbose=false}={},ensureSuccess=false) {
        if (typeof keyLength !== "number" || keyLength < 1 || !Number.isInteger(keyLength)) throw "the keyLength parameter must be an integer equal to or greater than 1!";
        else if (typeof substringLength !== "number" || substringLength < 0 || !Number.isInteger(substringLength)) throw "the substringLength parameter must be an integer equal to or greater than 0!";
        else if (typeof padSymbol !== "string" || padSymbol !== "" && padSymbol.length !== 1) throw "the padSymbol parameter must be a string of length 1!";
        else if (typeof inBetween !== "undefined" && (typeof inBetween !== "string" || inBetween !== "" && inBetween.length !== 1)) throw "the inBetween parameter, if provided, must be a string of length 1!";

        msg = Ekstra.padMsg(msg,substringLength,padSymbol);

        const _ch1 = Ekstra.shuffleString(Ekstra.completeCharset(Ekstra.extractCharset(msg+padSymbol),ch1));

        let _ch2: string;
        if (inBetween !== "")
            _ch2 = Ekstra.randomCharset(ch2,inBetween) + inBetween;
        else
            _ch2 = Ekstra.randomCharset(ch2+1);
        const key = Ekstra.randomKey(_ch1, keyLength);

        const encr = Ekstra.encrypt(msg,key,_ch1,_ch2.slice(0,ch2),substringLength,_ch2[ch2],padSymbol,verbose);
              //decr = Ekstra.decrypt(encr,key,_ch2.slice(0,ch2),_ch1,_ch2[ch2],verbose);
        
        if (ensureSuccess) {
            const decr = Ekstra.decrypt(encr,key,_ch2.slice(0,ch2),_ch1,_ch2[ch2],"",verbose);
            let succesful = true;
            if (decr !== msg) {
                succesful = false;
                console.error(`Message won't be decrypted properly! '${decr}'`);
            }

            return { encr, key, ch1:_ch1, ch2:_ch2.slice(0,ch2), inBetween:_ch2[ch2], padSymbol, succesful };
        }

        return { encr, key, ch1:_ch1, ch2:_ch2.slice(0,ch2), inBetween:_ch2[ch2], padSymbol };
    }
}
Object.freeze(Ekstra);
