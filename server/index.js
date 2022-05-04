const express = require('express');
const app = express();
const cors = require('cors');
const port = 3042;
const secp = require('@noble/secp256k1');
const {keccak_256} = require('@noble/hashes/sha3');
const {bytesToHex} = require('@noble/hashes/utils');

// localhost can have cross origin errors
// depending on the browser you use!
app.use(cors());
app.use(express.json());

//creating 3 private keys
let privateKey1 =secp.utils.randomPrivateKey();
let privateKey2 =secp.utils.randomPrivateKey();
let privateKey3 =secp.utils.randomPrivateKey();

//turning the private keys to hex-format
privateKey1 = Buffer.from(privateKey1).toString('hex'); //turns the private key from gibberish to hex-format
privateKey2 = Buffer.from(privateKey2).toString('hex');
privateKey3 = Buffer.from(privateKey3).toString('hex');

//creating public keys out of their private keys
let publicKey1 = secp.getPublicKey(privateKey1);
let publicKey2 = secp.getPublicKey(privateKey2);
let publicKey3 = secp.getPublicKey(privateKey3);

//turning them into hex-format
publicKey1 = Buffer.from(privateKey1).toString('hex')
publicKey2 = Buffer.from(privateKey2).toString('hex')
publicKey3 = Buffer.from(privateKey3).toString('hex')

//slicing so that we only have the last 40 characters
publicKey1 ="Ox" + publicKey1.slice(publicKey1.length -40); 
publicKey2 ="Ox" + publicKey2.slice(publicKey2.length -40);
publicKey3 ="Ox" + publicKey3.slice(publicKey3.length -40);


const balances = {
  [publicKey1]: 100,
  [publicKey2]: 50,
  [publicKey3]: 75,
}

/* app.METHOD(PATH, HANDLER), 
app is an instance of 'express', 
METHOD is an HTTP request method in lowercase, 
PATH is a path on the server, 
HANDLER is the function that will be executed, when the route is matched */
app.get('/balance/:address', (req, res) => {
  const {address} = req.params;
  const balance = balances[address] || 0; //'balance' is either set to an adress that exists or is set to zero
  res.send({ balance }); //we send {balance} to the client side???
});

app.post('/send', (req, res) => {
  const {recipient, amount, privateKey} = req.body;


  (async () => {
    //creating the message with the infos from client side:
    const message = JSON.stringify({
      to: recipient,
      amount: parseInt(amount)
    });
    
    //creating the messagehash
    const messageHash =bytesToHex(keccak_256(message));
    
    //getting the signature
    const signatureArray = await secp.sign(messageHash, privateKey,{recovered: true});
    
    
    //unpacking into signature and recovery-bit and turning signature into hex;
    let signature = signatureArray[0];
    signature = Buffer.from(signature).toString('hex');
    const recoverybit = signatureArray[1]
    

    //recover the public key
    let recoveredPublicKey =secp.recoverPublicKey(messageHash, signature, recoverybit)

    //turn into hex and slice appropriately
    recoveredPublicKey = Buffer.from(recoveredPublicKey).toString('hex');
    recoveredPublicKey = "0x" + recoveredPublicKey.slice(recoveredPublicKey.length - 40);
    
    //logging all the variables to the terminal for debugging
    console.log(`message ${message}`);
    console.log(`messageHash      ${messageHash}`);
    console.log(`signaturearray       ${signatureArray}`);
    console.log(`signature      ${signature}`);
    console.log(`recoverybit     ${recoverybit}`);
    console.log(`recoveredPublicKey        ${recoveredPublicKey}`); 
    
    if(secp.verify(signature, messageHash, recoveredPublicKey)){ //won't execute since recoveredPublicKey does not match the actual public key
      balances[recoveredPublicKey] -= amount;
      balances[recipient] = (balances[recipient] || 0) + +amount;
      res.send({ balance: balances[recoveredPublicKey] });
    }else {
      console.error("did not work");
      return;}
  })(); //do these () always need to be there for async-await to work?
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
  console.log(`Available Accounts \n ===================`)
  console.log(`(1) ${publicKey1} ${balances[publicKey1]}`);
  console.log(`(2) ${publicKey2} ${balances[publicKey2]}`);
  console.log(`(3) ${publicKey3} ${balances[publicKey3]}`);
  console.log(`\n Private Keys \n ======================`);
  console.log(`(1) ${privateKey1}`);
  console.log(`(2) ${privateKey2}`);
  console.log(`(3) ${privateKey3}`);
  console.log();
  
});
