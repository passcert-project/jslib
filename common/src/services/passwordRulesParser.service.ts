import { CustomCharacterData, NamedCharacterData, PasswordBlocklist, RuleData, } from '@passcert/pwrules-annotations';
import { PasswordRulesParserService as PasswordRulesParserServiceAbstraction } from '../abstractions/passwordRulesParser.service';

const Identifier = {
    ASCII_PRINTABLE: 'ascii-printable',
    DIGIT: 'digit',
    LOWER: 'lower',
    SPECIAL: 'special',
    UNICODE: 'unicode',
    UPPER: 'upper',
};

const BlockListIdentifier = {
    HIBP: "hibp",
    DEFAULT: "default",
}

const RuleName = {
    ALLOWED: "allowed",
    MAX_CONSECUTIVE: "max-consecutive",
    REQUIRED: "required",
    MIN_LENGTH: "minlength",
    MAX_LENGTH: "maxlength",
    MIN_CLASSES: "minclasses",
    BLOCK_LIST: "blocklist",
};

const PwDefaultOptions = {
    length: 14,
    ambiguous: false,
    number: true,
    minNumber: 1,
    uppercase: true,
    minUppercase: 0,
    lowercase: true,
    minLowercase: 0,
    special: false,
    minSpecial: 1,
    type: 'password',
    numWords: 3,
    wordSeparator: '-',
    capitalize: false,
    includeNumber: false,
};

let pwCanHaveNumbers: boolean = false;
let pwCanHaveUppercase: boolean = false;
let pwCanHaveLowercase: boolean = false;
let pwCanHaveSpecial: boolean = false;

let pwMinNumbers: number = 0;
let pwMinUppercase: number = 0;
let pwMinLowercase: number = 0;
let pwMinSpecial: number = 0;

let pwMaxNumbers: number = 0;
let pwMaxUppercase: number = 0;
let pwMaxLowercase: number = 0;
let pwMaxSpecial: number = 0;

let pwMinClasses: number = 1;
let pwBlocklist: string[] = [];

let requiredCustom: RuleData[] = [];
let allowedCustom: CustomCharacterData[] = [];


/* tslint:disable:no-string-literal */
export class PasswordRulesParserService implements PasswordRulesParserServiceAbstraction {

    convertToBitwardensObject(rules: RuleData[]): any {
        let lengthObj: any = {};

        lengthObj = this.applyPasswordLengthRules(rules);
        rules.forEach(r => {
            switch (r.name) {
                case RuleName.MAX_CONSECUTIVE:
                    // do nothing for now, doesn't seem to be this option in bitwarden
                    break;
                case RuleName.ALLOWED:
                    this.applyPasswordRules(r);
                    break;
                case RuleName.REQUIRED:
                    this.applyPasswordRules(r, true);
                    break;
                case RuleName.MIN_CLASSES:
                    pwMinClasses = r.value;
                    break;
                case RuleName.BLOCK_LIST:
                    let blist = PasswordBlocklist.getInstance();
                    // TODO: maybe just read here instead of the parser having the blocklisted words already
                    // FIXME: Only works for default for now. To work with HIBP, it would have to be at the generation of the pw. Here would just go the value to let the generation service know what to do.
                    pwBlocklist = r.value;
                    break;
            }
        });

        const siteOptions = {
            length: lengthObj['length'],
            number: pwCanHaveNumbers,
            minNumber: pwMinNumbers,
            uppercase: pwCanHaveUppercase,
            minUppercase: pwMinUppercase,
            lowercase: pwCanHaveLowercase,
            minLowercase: pwMinLowercase,
            special: pwCanHaveSpecial,
            minSpecial: pwMinSpecial,
            type: 'smartpassword',
            minLength: lengthObj['minLength'] !== 0 ? lengthObj['minLength'] : PwDefaultOptions['length'],
            maxLength: lengthObj['maxLength'] !== 0 ? lengthObj['maxLength'] : 128,
            reqNumber: pwCanHaveNumbers && pwMinNumbers > 0,
            reqUpper: pwCanHaveUppercase && pwMinUppercase > 0,
            reqLower: pwCanHaveLowercase && pwMinLowercase > 0,
            reqSpecial: pwCanHaveSpecial && pwMinSpecial > 0,
            allowedNumber: pwCanHaveNumbers,
            allowedUpper: pwCanHaveUppercase,
            allowedLower: pwCanHaveLowercase,
            allowedSpecial: pwCanHaveSpecial,
            minClasses: pwMinClasses,
            blocklist: pwBlocklist,
            reqCustom: requiredCustom,
            allowedCustom: allowedCustom,
            maxNumber: pwMaxNumbers,
            maxUppercase: pwMaxUppercase,
            maxLowercase: pwMaxLowercase,
            maxSpecial: pwMaxSpecial,
        };

        const aux = Object.assign({}, PwDefaultOptions, siteOptions);
        return aux;
    }

    resetRulesReferences(): void {
        pwCanHaveNumbers = false;
        pwCanHaveUppercase = false;
        pwCanHaveLowercase = false;
        pwCanHaveSpecial = false;

        pwMinNumbers = 0;
        pwMinUppercase = 0;
        pwMinLowercase = 0;
        pwMinSpecial = 0;

        pwMaxNumbers = 0;
        pwMaxUppercase = 0;
        pwMaxLowercase = 0;
        pwMaxSpecial = 0;

        pwMinClasses = 1;
        pwBlocklist = [];

        requiredCustom = [];
        allowedCustom = [];
    }


    private applyPasswordLengthRules(rules: RuleData[]) {
        // get the min and max length of password
        let lengthObj: any = {};
        let minLeng = 0;
        let maxLeng = 0;
        let pwLeng = PwDefaultOptions['length'];

        rules.forEach((r: any) => {
            if (r.name === RuleName.MIN_LENGTH) {
                minLeng = r.value;
            }
            if (r.name === RuleName.MAX_LENGTH) {
                maxLeng = r.value;
            }
        });

        if (maxLeng > minLeng) {
            // max is bigger than min
            if (maxLeng < pwLeng) {
                // max is lower than default. Update default
                pwLeng = maxLeng;
            } else if (minLeng > pwLeng) {
                pwLeng = minLeng;
            }

        } else if (maxLeng === minLeng) {
            // password must have exactly the minLeng = maxLeng
            pwLeng = minLeng;
        } else {
            // max is lower than min

            if (maxLeng !== 0 && maxLeng < pwLeng) {
                // exists a max value and it's lower than the default value
                pwLeng = maxLeng;
            } else if (pwLeng < minLeng) {
                pwLeng = minLeng;
            }
        }
        lengthObj = { minLength: minLeng, maxLength: maxLeng, length: pwLeng };
        return lengthObj;
    }

    private applyPasswordRules(rule: RuleData, required: boolean = false): void {

        let requiredValue = 0;
        if (required) {
            requiredValue = 1;
        }

        rule.value.forEach((charClass: NamedCharacterData | CustomCharacterData) => {
            if (charClass instanceof NamedCharacterData) {
                switch (charClass.name) {
                    case Identifier.LOWER:
                        pwCanHaveLowercase = true;
                        // check for minChars. If it's undefined, then set to the default value: 1 for required, 0 for allowed.
                        if (charClass.minChars !== undefined) {
                            pwMinLowercase = Number(charClass.minChars);
                            pwMaxLowercase = Number(charClass.maxChars);
                        } else if (pwMinLowercase < 1) {
                            // there is no maxChars by "default"
                            pwMinLowercase = requiredValue;
                        }

                        break;
                    case Identifier.DIGIT:
                        pwCanHaveNumbers = true;

                        if (charClass.minChars !== undefined) {
                            pwMinNumbers = Number(charClass.minChars);
                            pwMaxNumbers = Number(charClass.maxChars);
                        } else if (pwMinNumbers < 1) {
                            // there is no maxChars by "default"
                            pwMinNumbers = requiredValue;
                        }
                        break;
                    case Identifier.UPPER:
                        pwCanHaveUppercase = true;

                        if (charClass.minChars !== undefined) {
                            console.log("UPPER => ", charClass);
                            pwMinUppercase = Number(charClass.minChars);
                            console.log(pwMinUppercase);
                            pwMaxUppercase = Number(charClass.maxChars);
                            console.log(pwMaxUppercase);
                        } else if (pwMinUppercase < 1) {
                            // there is no maxChars by "default"
                            pwMinUppercase = requiredValue;
                        }
                        break;
                    case Identifier.SPECIAL:
                        pwCanHaveSpecial = true;
                        if (charClass.minChars !== undefined) {
                            pwMinSpecial = Number(charClass.minChars);
                            pwMaxSpecial = Number(charClass.maxChars);
                        } else if (pwMinSpecial < 1) {
                            // there is no maxChars by "default"
                            pwMinSpecial = requiredValue;
                        }
                        break;
                    case Identifier.ASCII_PRINTABLE:
                        pwCanHaveLowercase = true;
                        // not possible to set min or max range, so stays the default.
                        if (pwMinLowercase < 1) {
                            pwMinLowercase = requiredValue;
                        }
                        pwCanHaveNumbers = true;
                        if (pwMinNumbers < 1) {
                            pwMinNumbers = requiredValue;
                        }
                        pwCanHaveUppercase = true;
                        if (pwMinUppercase < 1) {
                            pwMinUppercase = requiredValue;
                        }
                        pwCanHaveSpecial = true;
                        if (pwMinSpecial < 1) {
                            pwMinSpecial = requiredValue;
                        }
                        break;
                }
            }
            else if (charClass instanceof CustomCharacterData) {
                if (required) {
                    // push the rule, it will be easier to handle 'required: u, l;' cases 
                    let ruleAlreadyExists = requiredCustom.findIndex(x => x.name === rule.name && x.value === rule.value);
                    if (ruleAlreadyExists === -1) {
                        requiredCustom.push(rule);
                    }
                } else {
                    // TODO: maybe needs to be adapted as the one above
                    allowedCustom.push(charClass);
                }
            }
        });
    }
}

