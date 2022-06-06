package DSCoinPackage;

import HelperClasses.Pair;

public class Moderator
 {
  public void initializeDSCoin(DSCoin_Honest DSObj, int coinCount){
    int count = coinCount;
    int c = 0; // iterates over memberlist
    int j = 100000;
    int d =0;// 
    int l = j; 
    // Distributing coins
    while(count > 0){
      Transaction[] arr = new Transaction[DSObj.bChain.tr_count];  
      for(int i =0; i <arr.length; i++){
        Transaction t = new Transaction();
        Members moderator = new Members();
        moderator.UID = "Moderator";
        t.Source = moderator;
        t.Destination = DSObj.memberlist[c];
        t.coinID = Integer.toString(j);
        t.coinsrc_block = null;
        arr[i] = t;
        count--;
        j++;
        c++;
        if(c >= DSObj.memberlist.length){
          c = 0;        
        }       
      }
      // updating my coins of all members
      TransactionBlock block = new TransactionBlock(arr);
      DSObj.bChain.InsertBlock_Honest(block);
      for(int i = 0; i < block.trarray.length; i++){
        Pair<String, TransactionBlock> p = new  Pair<String, TransactionBlock>("", null);
        p.first = Integer.toString(l);
        p.second = DSObj.bChain.lastBlock;
        DSObj.memberlist[d].mycoins.add(p);
        l++;
        d++;
        if(d >= DSObj.memberlist.length){
          d = 0;           
         }
      }     
    }
    // updating latest coin ID
    DSObj.latestCoinID = Integer.toString(j-1);
    return;
  }
 
    // use find longest valid 
    public void initializeDSCoin(DSCoin_Malicious DSObj, int coinCount) {
    int count = coinCount;
    int c = 0;
    int j = 100000;
    int d =0;
    int l = j;   
    while(count > 0){      
      Transaction[] arr = new Transaction[DSObj.bChain.tr_count];  
      for(int i =0; i <arr.length; i++){
        Transaction t = new Transaction();
        Members moderator = new Members();
    moderator.UID = "Moderator";
    t.Source = moderator;
    t.Destination = DSObj.memberlist[c];
    t.coinID = Integer.toString(j);
    t.coinsrc_block = null;
    arr[i] = t;
    count--;
    j++;
    c++;
    if(c >= DSObj.memberlist.length){
    c = 0;          
    }        
    }
      
     TransactionBlock block = new TransactionBlock(arr);
      
      DSObj.bChain.InsertBlock_Malicious(block);     
         
      
      for(int i = 0; i < block.trarray.length; i++){
        Pair<String, TransactionBlock> p = new  Pair<String, TransactionBlock>("", null);
        p.first = Integer.toString(l);      
        p.second = DSObj.bChain.FindLongestValidChain();     
        DSObj.memberlist[d].mycoins.add(p);
        l++;
        d++;
        if(d >= DSObj.memberlist.length){
          d = 0;          
         }
        
      }
    }   
    DSObj.latestCoinID = Integer.toString(j-1);
    return;
  } 
}
