'use strict'

const crypto = require('crypto')

let encryptValue, decryptValue, encryptObject, decryptObject

const decrypt = (pw, algo, enc) => (value) => {
  const decipher = crypto.createDecipher(algo, pw)

  return JSON.parse(decipher.update(value, enc, 'utf8') +
    decipher.final('utf8'))
}

const encrypt = (pw, algo, enc) => (value) => {
  const cipher = crypto.createCipher(algo, pw)

  return cipher.update(JSON.stringify(value), 'utf8', enc) +
    cipher.final(enc)
}

function cryptFunction (type) {
  return function (object, keys, isArray) {
    var objectKeys
    if (!isArray) objectKeys = Object.keys(object)
    var cryptValue = (type === 'encrypt') ? encryptValue : decryptValue
    var cryptObject = (type === 'encrypt') ? encryptObject : decryptObject
    var output = isArray ? [] : {}
    var length = isArray ? object.length : objectKeys.length

    for (var i = 0; i < length; i++) {
      var key = isArray ? i : objectKeys[i]
      if (!keys.length || (!isArray && keys.indexOf(key) === -1)) {
        if (typeof object[key] !== 'object') {
          output[key] = cryptValue(object[key])
        } else if (Array.isArray(object[key])) {
          output[key] = cryptObject(object[key], keys, true)
        } else {
          output[key] = cryptObject(object[key], keys)
        }
      } else {
        output[key] = object[key]
      }
    }

    return output
  }
}

exports.encrypt = function (object, password, config) {
  config = config || {}
  const encoding = config ? (config.encoding || 'hex') : 'hex'
  const algorithm = config ? (config.algorithm || 'aes256') : 'aes256'
  const keys = config.keys || []

  if (!object || typeof object !== 'object' || Array.isArray(object)) {
    throw new Error('First argument must be an object.')
  }

  if (!password) {
    throw new Error('Password is required.')
  }

  encryptValue = encrypt(password, algorithm, encoding)
  encryptObject = cryptFunction('encrypt')
  return encryptObject(object, keys)
}

exports.decrypt = function (object, password, config) {
  config = config || {}
  const encoding = config ? (config.encoding || 'hex') : 'hex'
  const algorithm = config ? (config.algorithm || 'aes256') : 'aes256'
  const keys = config.keys || []

  if (!object || typeof object !== 'object' || Array.isArray(object)) {
    throw new Error('First argument must be an object.')
  }

  if (!password) {
    throw new Error('Password is required.')
  }

  decryptValue = decrypt(password, algorithm, encoding)
  decryptObject = cryptFunction('decrypt')
  return decryptObject(object, keys)
}
