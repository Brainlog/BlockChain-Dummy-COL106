package DSCoinPackage;

import HelperClasses.CRF;

public class BlockChain_Honest {

  public int tr_count;
  public static final String start_string = "DSCoin";
  public TransactionBlock lastBlock;

  public void InsertBlock_Honest (TransactionBlock newBlock) {
    // Creating a new Transaction Block, Building Tree and connecting with chain
    TransactionBlock block = new TransactionBlock(newBlock.trarray);
    CRF obj = new CRF(64);
    block.previous = lastBlock;
    lastBlock = block;

    // computing nonce and dgst 
    int s = 1000000001;
    while(true){
      String s1 = Integer.toString(s);
      String s2 = "";
      if(lastBlock.previous == null){
        s2 = obj.Fn(start_string + "#" + lastBlock.trsummary + "#" + s1);
      }
      else{
      s2 = obj.Fn(lastBlock.previous.dgst + "#" + lastBlock.trsummary + "#" + s1);
      }
      boolean chk = true;
      for(int i = 0; i < 4; i++){
        if(s2.charAt(i) != '0'){
          chk = false;
        }


      }
      if(chk){
        lastBlock.dgst = s2; // if chk is true this meant it found a 10 digit string for which dgst has initial 4 digits 0
        lastBlock.nonce = s1; // Nonce
        break;

      }
      s++;
    }
  }
}
