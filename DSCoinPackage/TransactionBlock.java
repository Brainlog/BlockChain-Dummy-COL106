package DSCoinPackage;

import HelperClasses.MerkleTree;
import HelperClasses.CRF;

public class TransactionBlock {

  public Transaction[] trarray;
  public TransactionBlock previous;
  public MerkleTree Tree;
  public String trsummary;
  public String nonce;
  public String dgst;

  TransactionBlock(Transaction[] t) {
    // setting all attributes
    trarray = new Transaction[t.length];
    for(int i = 0; i < t.length; i++) {
      trarray[i] = t[i];
    }
    
    previous = null;
    Tree = new MerkleTree();
    Tree.Build(t);
    Tree.numdocs = t.length;
    trsummary = Tree.rootnode.val;
    dgst = null;   
  }
  
  public boolean checkTransaction (Transaction t) throws MissingTransactionException {

   
    if(this.previous == null){
      return true;
    }
    else{
      // finding whether transaction exist in block
    boolean found = false;
    for(int i =0; i < this.trarray.length; i++){
      if(this.trarray[i] == t){
        found = true;
        break;
      }
    }
    if(found == false){
      throw new MissingTransactionException();
    }


    
   
    if(t.coinsrc_block == null){
    
      boolean valid = true;
               
      return valid;
    }
  
    else{
      // checking in coin src block
    boolean valid = false;
    int n = t.coinsrc_block.trarray.length;
    for(int i = 0; i < n; i++) {
      if(t.coinID.equals(t.coinsrc_block.trarray[i].coinID) && t.Source == t.coinsrc_block.trarray[i].Destination ){
        valid = true;
      }  
    }
    TransactionBlock temp = this;
    // checking in intermediate blocks
    
    while(temp.previous != t.coinsrc_block){
      n = temp.previous.trarray.length;
      for(int i = 0; i < n; i++) {
        if(t.coinID.equals(temp.previous.trarray[i].coinID)){
          valid = false;
        }
      }
      temp = temp.previous;
    }
    return valid;
  }
  }
 }


}

