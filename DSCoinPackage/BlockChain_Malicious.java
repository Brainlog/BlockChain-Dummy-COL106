package DSCoinPackage;

import HelperClasses.CRF;
import HelperClasses.MerkleTree;

public class BlockChain_Malicious {

  public int tr_count;
  public static final String start_string = "DSCoin";
  public TransactionBlock[] lastBlocksList;

  public static boolean checkTransactionBlock (TransactionBlock tB) {
    CRF obj = new CRF(64);
    boolean chk = true;
    // Checking if tB.dgst has initial 4 values 0
    for(int i =0; i < 4; i++){
      if(tB.dgst.charAt(i) != '0'){
        
        chk = false;
        break;
      }
    }
    // checking dgst
    if(tB.previous == null){
      if(!tB.dgst.equals(obj.Fn(start_string + "#" + tB.trsummary + "#" + tB.nonce))){
        
        chk = false;
      }
    }
    else{
      if(!tB.dgst.equals(obj.Fn(tB.previous.dgst + "#" + tB.trsummary + "#" + tB.nonce))){
        
       
        
        chk = false;
      }
    }
    // Building a tree from trarray and comparing with tree.rootnode.val
    MerkleTree tree = new MerkleTree();
    tree.Build(tB.trarray);
   
    if(!tree.rootnode.val.equals(tB.trsummary)){
     
      chk = false;
    } 
    
    try{ // checking every transaction for valid
    for(int i = 0; i < tB.trarray.length; i++){
     
    
      if(tB.checkTransaction(tB.trarray[i]) == false){
        
        chk = false;
        break;
      }

    }
  }
  catch(MissingTransactionException e){
    System.out.print(e.getMessage());

  }




    return chk;
  }

  public TransactionBlock FindLongestValidChain () {
    // if list has no elements it should return null
    if(lastBlocksList == null){
     
      return null;
    }
    else if(lastBlocksList[0] == null){
     
      return null;
    }
   else{
     // Making an array which stores last valid block for every leaf block
    
    TransactionBlock[] arr = new TransactionBlock[lastBlocksList.length];
    TransactionBlock temp;
   for(int i = 0; i < arr.length; i++){
     temp = lastBlocksList[i];
     
   
     while(checkTransactionBlock(temp) != true){
      
       
       temp = temp.previous;
     }
     arr[i] = temp;
   

   }
 
   // computing the length from start to last valid and whose max will be returned
   int max = 0;
   TransactionBlock need = null;
   for(int i = 0; i < arr.length; i++){
     temp = arr[i];
     int s = 0;

     while(temp != null){
       s++;
       temp = temp.previous;
     }
     if(max < s){
       max = s;
       need = arr[i];
       
     }
   }
  
  

    return need;
  }
  }

  public void InsertBlock_Malicious (TransactionBlock newBlock) {
    

    int j =0;
    // for lastblocklist null, no need to find longest valid
    if(lastBlocksList == null){
      lastBlocksList = new TransactionBlock[1];
      lastBlocksList[0] = newBlock;
      lastBlocksList[0].previous = null;
      j = 0;
      return;
    }
    else if(lastBlocksList[0] == null){
      
      lastBlocksList = new TransactionBlock[1];
      lastBlocksList[0] = newBlock;
      lastBlocksList[0].previous = null;
      j = 0;
      int s = 1000000001;
      CRF obj = new CRF(64);
      while(true){
        String s1 = Integer.toString(s);
        String s2 = "";
        
          s2 = obj.Fn(start_string + "#" + lastBlocksList[0].trsummary + "#" + s1);
        
        
        boolean chk = true;
        for(int i = 0; i < 4; i++){
          if(s2.charAt(i) != '0'){
            chk = false;
          }
  
  
        }
        if(chk){
          lastBlocksList[0].dgst = s2;
          lastBlocksList[0].nonce = s1;
          break;
  
        }
        s++;
      }
      return;

    }
    else{
      // connecting block to the returned block of findlongestValid
      newBlock.previous = this.FindLongestValidChain();
     
      boolean check = false;
      int i =0;
    
      
      while(!check && i < lastBlocksList.length){
        if(newBlock.previous == lastBlocksList[i]){
          check = true;
          j = i;
        }
        i++;
      }
      // if check is true this means longest valid block is in lastblocklist and no need to increase leaf blocks just replace that one
      if(check){
        
        lastBlocksList[j] = newBlock;                
      }
      // else add a new block in lastblock list 
      else{
        // resizing lastblock list
        TransactionBlock[] arr = new TransactionBlock[lastBlocksList.length + 1];
        int i_6 = 0;
        for(int i_5 = 0; i_5 < lastBlocksList.length; i_5++){
          arr[i_5] = lastBlocksList[i_5];
          i_6++;
        }
        arr[i_6] = newBlock;
        lastBlocksList = arr;
        j = arr.length -1;

      }

    }
    CRF obj = new CRF(64);

    // computing dgst and nonce
    int s = 1000000001;
    while(true){
      String s1 = Integer.toString(s);
      String s2 = "";
      if(lastBlocksList[j].previous == null){
         s2 = obj.Fn(start_string + "#" + lastBlocksList[j].trsummary + "#" + s1);
      }
      else{
       s2 = obj.Fn(lastBlocksList[j].previous.dgst + "#" + lastBlocksList[j].trsummary + "#" + s1);
      }
      boolean chk = true;
      for(int i = 0; i < 4; i++){
        if(s2.charAt(i) != '0'){
          chk = false;
        }


      }
      if(chk){
        lastBlocksList[j].dgst = s2;
        lastBlocksList[j].nonce = s1;
        break;

      }
      s++;
    }


    return;
  }

      

      
    
    


  
}
