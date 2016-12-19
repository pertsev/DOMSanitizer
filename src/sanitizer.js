// DOMSanitizer.

// Links:
// Github: https://github.com/ptresearch/DOMSanitizer

/* global acorn: false, DOMPurify: false, window: false, module: false, define: false */
(function(factory) {
    'use strict';
    var root = typeof window === 'undefined' ? null : window;
    if (typeof define === 'function' && define.amd) {
        define(function() {
            return factory(root);
        });
    } else if (typeof module !== 'undefined') {
        module.exports = factory(root);
    } else {
        root.DOMSanitizer = factory(root);
    }
}(function factory(window) {
    'use strict';

    if (!String.prototype.trim) {
        (function() {
            // Make sure we trim BOM and NBSP
            var rtrim = /^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g;
            String.prototype.trim = function() {
                return this.replace(rtrim, '');
            };
        }());
    }

    var DOMSanitizer = function(window) {
        return factory(window);
    };

    DOMSanitizer.version = '0.1.0';

    if (!window || !window.document || window.document.nodeType !== 9 || !acorn || !DOMPurify || !DOMPurify.isSupported) {
        DOMSanitizer.isSupported = false;
        return DOMSanitizer;
    } else {
        DOMSanitizer.isSupported = true;
    }

    var document = window.document;
    var implementation = document.implementation;
    
    /* DOMPurify's function to create a config set. */
    var _addToSet = function(set, array) {
        var l = array.length;
        while (l--) {
            set[array[l]] = true;
        }
        return set;
    };

    /* Returned value if injection was found. */
    var CLEAN = '';
    
    /* Contexts enabled by default. */
    var CONTEXTS = ['callback', 'url', 'attr', 'js', 'dom'];
    
    /* Forbidden AST node types of ESTree */
    var FORBIDDEN_AST_NODES = _addToSet({}, [
        'ArrayPattern', 'ArrowFunctionExpression', 'AssignmentExpression', 'CallExpression',
        'ExportAllDeclaration', 'ExportDefaultDeclaration', 'ExportNamedDeclaration', 'ExportSpecifier',
        'ForOfStatement', 'ForInStatement', 'FunctionDeclaration', 'FunctionExpression',
        'ImportDeclaration', 'ImportDefaultSpecifier', 'ImportNamespaceSpecifier', 'ImportSpecifier',
        'NewExpression', 'ObjectPattern', 'SpreadElement', 'TaggedTemplateExpression',
        'VariableDeclaration', 'WithStatement', 'YieldExpression'
    ]);

    /* Check if an input is JSON */
    var _isJSON = function(s) {
        try {
            var json = JSON.parse(s);
            return typeof json === 'object';
        } catch(e) {
            return false;
        }
    };
        
    /* Access to 'obj' via 'path' for writing or reading */
    var _accessByString = function(obj, path, value) {
        path = path.replace(/\[(\w+)\]/g, '.$1');
        path = path.replace(/^\./, '');
        path = path.replace(/\.$/, '');
        var o = obj;
        var pList = path.split('.');
        var len = pList.length;
        for (var i = 0; i < len - 1; i++) {
            var elem = pList[i];
            if (o && elem in o) {
                o = o[elem];
            } else {
                return;
            }
        }
        if (arguments.length === 3) {
            o[pList[len - 1]] = value;
        }
        return o[pList[len - 1]];
    };

    /*
     * _initDocument
     *
     * @param  a string of dirty markup
     * @return a DOM, filled with the dirty markup
     */
    var _initDocument = function(html) {
        var doc, body;
        try {
            doc = new DOMParser().parseFromString(html, 'text/html');
        } catch (e) {}

        /* If DOMParser is not accessible */
        if (!doc || !doc.documentElement) {
            doc = implementation.createHTMLDocument('');
            body = doc.body;
            body.parentNode.removeChild(body.parentNode.firstElementChild);
            body.outerHTML = html;
        }
        return doc;
    };

    /*
     *  Input normalization funtion.
     *  It supports html entities, octal, hex, and unicode decodings.
     *
     *  @param {string} s - input string.
     *  @return {string} normalizad input.
     */
    var _normalizeInput = function(s) {
        var tmp;
        var textArea = document.createElement('textarea');
        do {
            tmp = s;
            textArea.innerHTML = s;
            s = textArea.value;
            try {
                s = decodeURIComponent(s);
            } catch (e) {}
        } while (tmp !== s);
        s = s.replace(/(?:\r\n|\n|\r|\t)/g, '');
        return s;
    };
    
    /* JavaScript tokenizer */
    var _getJSTokens = function(s) {
        if (s === '') {
            return [''];
        }
        var re = /((['"])(?:(?!\2|\\).|\\(?:\r\n|[\s\S]))*(\2)?|`(?:[^`\\$]|\\[\s\S]|\$(?!\{)|\$\{(?:[^{}]|\{[^}]*\}?)*\}?)*(`)?)|(\/\/.*)|(\/\*(?:[^*]|\*(?!\/))*(\*\/)?)|(\/(?!\*)(?:\[(?:(?![\]\\]).|\\.)*\]|(?![\/\]\\]).|\\.)+\/(?:(?!\s*(?:\b|[\u0080-\uFFFF$\\'"~({]|[+\-!](?!=)|\.?\d))|[gmiyu]{1,5}\b(?![\u0080-\uFFFF$\\]|\s*(?:[+\-*%&|^<>!=?({]|\/(?![\/*])))))|((?:0[xX][\da-fA-F]+|0[oO][0-7]+|0[bB][01]+|(?:\d*\.\d+|\d+\.?)(?:[eE][+-]?\d+)?))|((?!\d)(?:(?!\s)[$\w\u0080-\uFFFF]|\\u[\da-fA-F]{4}|\\u\{[\da-fA-F]{1,6}\})+)|(--|\+\+|&&|\|\||=>|\.{3}(?:(?:[a-zA-Z]+[a-zA-Z0-9]*)|(?:'[^']*[^\\]'?)|(?:"[^"]*[^\\]"?)|(?:`[^`]*[^\\]`?))|(?:[+\-*\/%&|^]|<{1,2}|>{1,3}|!=?|={1,2})=?|[?:~]|[;,.[\](){}])|(\s+)|(^$|[\s\S])/g;
        var tokens = [];
        var match;
        while ((match = re.exec(s)) != null) {
            tokens.push(match[0]);
        }
        return tokens;
    };
  
    /*
     *  _isJSInjection
     *
     *  @param {string} s - an input string.
     *  @return {boolean} Returns true if input can be parsed and its AST contains dangerous ECMAScript code, otherwise returns false.
     */
    var _isJSInjection = function(s, options) {
        if (typeof options !== 'object') {
            options = {};
        }
        var parseOnce = options.parseOnce || false;
        var forbidden = FORBIDDEN_AST_NODES;
        var ctx, tokens, curToken;
        var isInjection = false;

        /* Define extension for Acorn's function. */
        var checkPolicy = function(node, type) {
            if(forbidden[type]) {
                // Pass expressions like 'a=1' to reduce false positive,
                // but handles expression like 'window.foo = 1', '[window.foo]=1', 'foo = alert(1)', 'foo = function foo(){}'

                // We can not see 'ArrayPattern' node in 'finishNode' function.
                // We see this node as 'ArryExpression' that will be transformed to 'ArrayPattern' in Acorn later.
                if (type === 'AssignmentExpression') {
                    if (node.left.type === 'MemberExpression'  ||
                            node.left.type === 'ArrayPattern'  ||
                            node.left.type === 'ObjectPattern' ||
                            node.left.name === 'location') {
                        isInjection = true;
                        return;
                    }
                    if (node.right.type === 'FunctionExpression' ||
                            node.right.type === 'CallExpression' ||
                            node.right.type === 'MemberExpression') {
                        isInjection = true;
                        return;
                    }
                } else {
                    isInjection = true;
                    return;
                }
            }
        };

        /* Extend default Acorn's methods. */
        acorn.plugins.wafjs = function(parser) {
            parser.extend('finishNode', function(nextMethod) {
                return function(node, type) {
                    checkPolicy(node, type);
                    return nextMethod.call(this, node, type);
                };
            });

            parser.extend('finishNodeAt', function(nextMethod) {
                return function(node, type, pos, loc) {
                    checkPolicy(node, type);
                    return nextMethod.call(this, node, type, pos, loc);
                };
            });
        };
        
        ctx = s;
        // List of tokens.
        tokens = _getJSTokens(ctx);
        // Hard tokens, that can be deleted from string without parsing.
        var hardTokens = ['}', ')', '.', '*', '/'];
        curToken = 0;
        do {
            if (hardTokens.indexOf(ctx[0]) === -1) {
                try {
                    acorn.parse(ctx, {ecmaVersion: 6, allowImportExportEverywhere: true, allowReserved: true, plugins: {wafjs: true}});
                } catch(e) {}
                if (isInjection) {
                    return true;
                }
            }
            // Delete the next token from the context string.
            ctx = ctx.substring(tokens[curToken].length);
            curToken += 1;
        } while(ctx.length > 0 && !parseOnce);
        return false;
    };

    /*
     *  _isJSInjectionLoose
     *
     *  @param {string} s - an input string.
     *  @return {boolean} Returns true if input can be parsed (even with errors) and its AST contains dangerous ECMAScript code, otherwise returns false.
     */
    var injection = ['type', 'string'];

    var _isJSInjectionLoose = function(s, options) {
        if (typeof options !== 'object') {
            options = {};
        }
        var parseOnce = options.parseOnce || false;
        var forbidden = FORBIDDEN_AST_NODES;
        var ctx, tokens, curToken;
        var isInjection = false;

        /* Define extension for Acorn's function. */
        var checkPolicy = function(node, type) {
            if(forbidden[type]) {
                if (type === 'AssignmentExpression') {
                    var beforeNode = node.parser.input.slice(0, node.start).trim();
                    var afterNode = node.parser.input.slice(node.end).trim();
                    var beforeTypes = [',', ';', '{', '(', '[', ':', ''];
                    var afterTypes = [',', ';', ']', ')', '}', ''];
                    if (beforeTypes.indexOf(beforeNode.slice(-1)) !== -1 && afterTypes.indexOf(afterNode.slice(0, 1)) !== -1) {
                        if ((node.left.type === 'MemberExpression' ||
                            node.left.type === 'ArrayPattern' ||
                            node.left.type === 'ObjectPattern' ||
                            node.left.name === 'location') &&
                            (node.right.name !== '✖' &&
                            node.right.type !== 'AssignmentExpression' &&
                            node.right.type !== 'UnaryExpression')) {
                            console.log('LEFT', node);
                            isInjection = true;
                            injection = [type, node.toString()];
                            return;
                        }
                        if (node.right.type === 'FunctionExpression' ||
                            node.right.type === 'CallExpression' ||
                            node.right.type === 'MemberExpression') {
                            console.log('RIGHT', node);
                            isInjection = true;
                            injection = [type, node.toString()];
                            return;
                        }
                    }
                } else if (type === 'WithStatement') {
                    if (node.object.type === 'Identifier') {
                        var bracketIndex = node.toString().slice(0, node.object.start - node.start).indexOf('(');
                        if (bracketIndex !== -1 && node.toString().slice(4, bracketIndex).trim() === '') {
                            isInjection = true;
                            injection = [type, node.toString()];
                            return;
                        }
                    }
                } else if (type === 'SpreadElement') {
                    var beforeSpreadNode = node.parser.input.slice(0, node.start).trim();
                    var afterSpreadNode = node.parser.input.slice(node.end).trim();
                    var beforeSpreadTypes = [',', '[', '(', ''];
                    var afterSpreadTypes = [',', ']', ')', ''];
                    if (beforeSpreadTypes.indexOf(beforeSpreadNode.slice(-1)) !== -1 && afterSpreadTypes.indexOf(afterSpreadNode.slice(0, 1)) !== -1) {
                        var argTypes = ['Identifier', 'ArrayExpression'];
                        var literalTypes = ['"', '\'', '`'];
                        if (argTypes.indexOf(node.argument.type) !== -1 && node.argument.name !== '✖') {
                            isInjection = true;
                            injection = [type, node.toString()];
                            return;
                        } else if (node.argument.type === 'Literal' && literalTypes.indexOf(node.argument.toString()[0]) !== -1) {
                            isInjection = true;
                            injection = [type, node.toString()];
                            return;
                        }
                    }
                } else {
                    isInjection = true;
                    injection = [type, node.toString()];
                    return;
                }
            }
        };

        /* Extend default Acorn's methods. */
        acorn.loose.pluginsLoose.wafjs = function(parser) {

            parser.extend('finishNode', function(nextMethod) {
                return function(node, type) {
                    var completeNode = nextMethod.call(this, node, type);
                    checkPolicy(node, type);
                    return completeNode;
                };

            });
            /*
            parser.extend('finishNodeAt', function(nextMethod) {
                return function(node, type, pos, loc) {
                    checkPolicy(node, type);
                    return nextMethod.call(this, node, type, pos, loc);
                };
            });
             */
        };

        ctx = s;
        // List of tokens.
        tokens = _getJSTokens(ctx);
        // Hard tokens, that can be deleted from string without parsing.
        var hardTokens = ['}', ')', '*', '/'];
        curToken = 0;
        do {
            if (hardTokens.indexOf(ctx[0]) === -1 || (ctx[0] === '.' && ctx.slice(0, 3) !== '...')) {
                acorn.loose.parse_dammit(ctx, {ecmaVersion: 6, allowImportExportEverywhere: true, allowReserved: true, pluginsLoose: {wafjs: true}});
                if (isInjection) {
                    return true;
                }
            }
            // Delete the next token from the context string.
            ctx = ctx.substring(tokens[curToken].length);
            curToken += 1;
        } while(ctx.length > 0 && !parseOnce);
        return false;
    };

    /*
     *  _isJSInjectionInAttr
     *
     *  @param {string} s - an input string.
     *  @return {boolean} Returns true if on* attribute value can be parsed and its AST contains dangerous ECMAScript code, otherwise returns false.
     */
    var _isJSInjectionInAttr = function(s) {
        var doc, attributes, name, l, children;
        var value;
        doc = _initDocument(s);
        children = doc.body.children;
        // In normal case the body should have only 1 child.
        if (children.length !== 1) {
            return true;
        }
        attributes = doc.body.childNodes[0].attributes;
        l = attributes.length;
        while (l--) {
            name = attributes[l].name.toLowerCase();
            if (/^on[a-z]{3,35}/.test(name)) {
                value = attributes[l].value;
                /*
                 * _isJSInjection func can be changed with _isJSInjectionLoose (tested)
                 * PS. In _sanitize.attr too.
                 */
                if (_isJSInjection(value, {parseOnce: true})) {
                    return true;
                }
                
                
            }
        }
        return false;
    };

    var _sanitize = Object.create({});

    /*
     *  Sanitization in Callback context.
     *
     *  @param {string} s - input string
     *  @return {string} If s does not contain a valid in DOM function name, returns original string s, otherwise returns empty string.
     */
    _sanitize.callback = function(s) {
        if (typeof _accessByString(window, s) === 'function') {
            return CLEAN;
        }
        return s;
    };

    /*
     * Basic sanitization for URL context.
     * It is hard to imlement full protection here because of peculiarities of data URI parsing in different browsers.
     * See http://blog.kotowicz.net/2012/04/fun-with-data-urls.html
     *     https://github.com/mauro-g/snuck/blob/master/payloads/uri_payloads
     *
     *  @param {string} s - input string.
     *  @return {string} If s does not contain JavaScript patterns, returns original string s, otherwise returns empty string.
     */
    _sanitize.url = function(s) {
        if (s.indexOf(':') === -1) {
            return s;
        }
        var re = /(?:(?:java|vb|j)script:|data:\W*(?:(?:text\/(?:html|xml)|image\/svg\+xml|application\/(?:xml|xhtml\+xml)):?\s*(?:;[\n\t\r ,;]?base64[^\,]*)?,?|,))/i;
        if (re.test(s)) {
            return CLEAN;
        }
        return s;
    };

    /*
     *  Sanitization in JavaScript context.
     *
     *  @param {string} s - an input string.
     *  @return {string} If s does not contain JavaScript patterns, returns original string s, otherwise returns empty string.
     */
    _sanitize.js = function(s) {
        if (!(/['"\=\;\(\)\[\]\{\}\.\`]|(?:export)|(?:import)/.test(s))) {
            return s;
        }
        // Injection index - character after that injected code starts
        var index;

        // "Single quote" context
        index = s.indexOf('\'');
        if (index !== -1 && _isJSInjection(s.slice(index + 1))) {
            return CLEAN;
        }
        // "Double quote" context
        index = s.indexOf('"');
        if (index !== -1 && _isJSInjection(s.slice(index + 1))) {
            return CLEAN;
        }
        // "as-is" context
        if (_isJSInjection(s)) {
            return CLEAN;
        }
        return s;
    };

    _sanitize.jsloose = function(s) {

        var _checkJSInjection = function(s) {
            if (!(/['"\=\;\(\)\[\]\{\}\.\`]|(?:export)|(?:import)/.test(s))) {
                return false;
            }
            // Injection index - character after that injected code starts
            var index;
            index = s.indexOf('\'');
            if (index !== -1 && _isJSInjectionLoose(s.slice(index + 1))) {
                return true;
            }
            // "Double quote" context
            index = s.indexOf('"');
            if (index !== -1 && _isJSInjectionLoose(s.slice(index + 1))) {
                return true;
            }
            // "as-is" context
            if (_isJSInjectionLoose(s)) {
                return true;
            }
            return false;
        };

        if (_isJSON(s)) {
            var jsonObj = JSON.parse(s);
            for (var key in jsonObj) {
                if (jsonObj.hasOwnProperty(key)) {
                    if (_checkJSInjection(key)) {
                        return CLEAN;
                    }
                    // if json object contains nested object => recursive call for object key and value.
                    if (typeof jsonObj[key] === 'object') {
                        var result = _sanitize.jsloose(JSON.stringify(jsonObj[key]));
                        if (result === CLEAN) {
                            return CLEAN;
                        }
                    }else if (_checkJSInjection(jsonObj[key])) {
                        return CLEAN;
                    }
                }
            }
        }else if (_checkJSInjection(s)) {
            return CLEAN;
        }
        return s;
    };

    /*
     *  Sanitization in HTML/DOM context.
     *
     *  @param {string} s - input string.
     *  @return {string[]} If s does not contain dangerous HTML, returns original string s, overwise returns empty string.
     */
    _sanitize.dom = function(s) {
        if (_isJSON(s)) {
            return s;
        }
        /*
         * Add hook to sanitize external protocols (e.g., http, https, ftp, ftps, tel, mailto) as DOMPurify allows them by default.
         * This hook changes scheme in address, thus violating policy.
         */
        DOMPurify.addHook('uponSanitizeAttribute', function(node, data) {
            if (data.attrName === 'href' || data.attrName === 'xlink:href' || data.attrName === 'action') {
                data.attrValue = 'schema://name#';
            }
        });
       /* 'WHOLE_DOCUMENT' should be set to true. The reason is the following:
         * '<script>alert(1)</script>' input will be parsed to
         * '<html><head><script>alert(1)></script></head><body></body></html>'. If 'WHOLE_DOCUMENT' is false
         * then input will be sanitized, bit DOMPurify.removed[] will not contain deleted <script> node.
         *
         * 'SAFE_FOR_TEMPLATES' and 'SAFE_FOR_JQUERY' should be set to true to sanitize data for templates systems and jQuery
         */
        DOMPurify.sanitize(s, {
            WHOLE_DOCUMENT: true,
            SAFE_FOR_TEMPLATES: true,
            SAFE_FOR_JQUERY: true,
            ALLOW_UNKNOWN_PROTOCOL: false
        });
        // Return clean, if a dangerous HTML was found.
        if (DOMPurify.removed.length > 0) {
            return CLEAN;
        }
        return s;
    };

    /*
     *  Sanitization in attribute-based context.
     *
     *  @param {string} s - input string.
     *  @return {string} If s does not contain dangerous JavaScript, returns original string s, overwise returns empty string.
     */
    _sanitize.attr =  function(s) {
        if (!(/['"\=\;\(\)\[\]\{\}\.\`]|(?:export)|(?:import)/.test(s))) {
            return s;
        }
        /*  $ - injection point, {} - injection's edges.
            Example: <img src='$'> -> <img src='{1' onerror='alert(1)}'>.
            Here we create a fake HTML documents based on user's input and find event handlers inside its markup.
            It is injection if on* attribute value is valid JS and contains dangerous JS.

            It is possible to use the following polyglot vector, but tests showed that performance is little changed:
            image = '<img bar="' + s + '"' + ' baz=\'' + s + '\'' +  ' bam=1 ' + s + ' >';
        */
       
        var image;
       
        image = '<img foo="' + s + '" >';
        if (_isJSInjectionInAttr(image)) {
            return CLEAN;
        }
        image = '<img bar=\'' + s +  '\' >';
        if (_isJSInjectionInAttr(image)) {
            return CLEAN;
        }
        image = '<img baz=1 ' + s + ' >';
        if (_isJSInjectionInAttr(image)) {
            return CLEAN;
        }
        
        if (_isJSInjection(s, {parseOnce: true})) {
            return CLEAN;
        }

        return s;
    };
    
    /*
     *  sanitize
     *
     *  @param {string} dirty     - input string.
     *  @param {object} options   - configuration object
     *
     *  @return {string} If input is safe in the specified contexts, returns original s, else returns empty string.
     */
    DOMSanitizer.sanitize = function(dirty, options) {
        if (dirty === '') {
            return dirty;
        }
        if (typeof options !== 'object') {
            options = {};
        }
        var contexts = _addToSet({}, options.CONTEXTS || CONTEXTS);
        var s = _normalizeInput(dirty);
        var ctx, item;
        // eslint-disable-next-line guard-for-in
        for (item in contexts) {
            ctx = item.toLowerCase();
            if (ctx in _sanitize && !_sanitize[ctx](s)) {
                if (ctx === 'jsloose') {
                    return injection;
                }
                return CLEAN;
            }
        }
        return dirty;
    };

    /*
     *  normalize.
     *  It supports html entities, octal, hex, and unicode decodings.
     *
     *  @param {string} s - input string.
     *  @return {string} normalizad input.
     */
    DOMSanitizer.normalize = _normalizeInput;

    return DOMSanitizer;
}));
