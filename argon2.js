const argon2 = require("argon2");

exports.hash = async function (options) {

    let argon2Options = {hashLength: options.hashLength || 32, timeCost: options.timeCost || 3, memoryCost: options.memoryCost || 4096, parallelism: options.parallelism || 1}
    let password = this.parse(options.password)
    
    switch (options.method || 'argon2i') {
        case 'argon2d':
            return await argon2.hash(password, { type: argon2.argon2d, ...argon2Options }) 
        case 'argon2i':
            return await argon2.hash(password, { type: argon2.argon2i, ...argon2Options })     
        case 'argon2id':
            return await argon2.hash(password, { type: argon2.argon2id, ...argon2Options }) 
      } 
  };

  exports.verify = async function (options) {
    let password = this.parse(options.password)
    let hash = this.parse(options.hash)
    return await argon2.verify(hash, password)
  };


