package DSCoinPackage;

import java.util.*;
import HelperClasses.Pair;
import HelperClasses.TreeNode;

public class Members
 {

  public String UID;
  public List<Pair<String, TransactionBlock>> mycoins;
  public Transaction[] in_process_trans;

  public void initiateCoinsend(String destUID, DSCoin_Honest DSobj) {
    // Making object of Transaction and providing all details
    Transaction tobj = new Transaction();
    Members member = new Members();
    for(int i =0; i < DSobj.memberlist.length; i++){
      member = DSobj.memberlist[i];
      if(member.UID.equals(destUID)){
        break;
      }
    } 
    tobj.Destination = member;
    tobj.Source = this;
    tobj.coinID = mycoins.get(0).first;
    tobj.coinsrc_block = mycoins.get(0).second;
    
    // making a new list and adding all elements from index 1 to end and assigning to mycoins
    List<Pair<String, TransactionBlock>> temp = new ArrayList<Pair<String, TransactionBlock>>();
    for(int i = 1; i < mycoins.size(); i++){
      temp.add(mycoins.get(i));
    }
    mycoins = temp;
    
    if(in_process_trans == null){
      in_process_trans = new Transaction[1];
      in_process_trans[0] = tobj;

    }
    else if(in_process_trans[0] == null){
     
      in_process_trans = new Transaction[1];
      in_process_trans[0] = tobj;
    }
    else{
      Transaction[] newList = new Transaction[in_process_trans.length + 1];
      int i = 0;
     while(i < in_process_trans.length){
       newList[i] = in_process_trans[i];
       i++;
     }
     newList[i] = tobj;
     in_process_trans = newList;           
    }

    // updating pending Transactions
    if(DSobj.pendingTransactions == null){
      DSobj.pendingTransactions = new TransactionQueue();

      DSobj.pendingTransactions.firstTransaction = tobj;
      DSobj.pendingTransactions.lastTransaction = tobj;
      DSobj.pendingTransactions.firstTransaction.next = null;
      DSobj.pendingTransactions.numTransactions = 1;
      return;

      
    }
    else{
      DSobj.pendingTransactions.AddTransactions(tobj);
      DSobj.pendingTransactions.numTransactions++;
      return;
  }
}



  public void initiateCoinsend(String destUID, DSCoin_Malicious DSobj) {
    // Making object of Transaction and providing all details
    Transaction tobj = new Transaction();
    Members member = new Members();
    for(int i =0; i < DSobj.memberlist.length; i++){
      member = DSobj.memberlist[i];
      if(member.UID.equals(destUID)){
        break;
      }
    } 
    tobj.Destination = member;
    tobj.Source = this;
    tobj.coinID = mycoins.get(0).first;
    tobj.coinsrc_block = mycoins.get(0).second;
    
    // making a new list and adding all elements from index 1 to end and assigning to mycoins
    List<Pair<String, TransactionBlock>> temp = new ArrayList<Pair<String, TransactionBlock>>();
    for(int i = 1; i < mycoins.size(); i++){
      temp.add(mycoins.get(i));
    }
    mycoins = temp;
   

    // updating in_process_trans after removing coin from mycoins
    
    if(in_process_trans == null){
      in_process_trans = new Transaction[1];
      in_process_trans[0] = tobj;

    }
    else if(in_process_trans[0] == null){
      
      in_process_trans = new Transaction[1];
      in_process_trans[0] = tobj;
    }
    else{
      Transaction[] newList = new Transaction[in_process_trans.length + 1];
      int i = 0;
     while(i < in_process_trans.length){
       newList[i] = in_process_trans[i];
       i++;
     }
     newList[i] = tobj;
     in_process_trans = newList;           
    }

    // updating pending Transactions
    if(DSobj.pendingTransactions == null){
      DSobj.pendingTransactions = new TransactionQueue();

      DSobj.pendingTransactions.firstTransaction = tobj;
      DSobj.pendingTransactions.lastTransaction = tobj;
      DSobj.pendingTransactions.firstTransaction.next = null;
      DSobj.pendingTransactions.numTransactions = 1;
      return;

      
    }
    else{
      DSobj.pendingTransactions.AddTransactions(tobj);
      DSobj.pendingTransactions.numTransactions++;
      return;

  } 
}
   
    
  


  

  public Pair<List<Pair<String, String>>, List<Pair<String, String>>> finalizeCoinsend (Transaction tobj, DSCoin_Honest DSObj) throws MissingTransactionException {
    // checking whether tobj exist or not
    boolean check = false;
    TransactionBlock temp =  DSObj.bChain.lastBlock;
    TransactionBlock temp_2 = DSObj.bChain.lastBlock;
    
    Transaction trans = new Transaction();
    int j =0;
    while(temp_2 != null && !check){
      for(int i =0; i < temp_2.trarray.length; i++){
        if(tobj == temp_2.trarray[i]){
          trans = tobj;
          j = i;
          check = true;
          temp = temp_2;      
          break;
        }
      }
      if(check)
      break;
      temp_2 = temp_2.previous;
    }

    // creating a pair of list that store sibling coupled path to root

    List<Pair<String, String>> l = new ArrayList<Pair<String, String>>();
    
    Pair<List<Pair<String, String>>, List<Pair<String, String>>> pair = new  Pair<List<Pair<String, String>>, List<Pair<String, String>>>(l,l); 
  
    if(check){
      // Traversing in tree of iterated blocks till node that has value related to transaction
      
      TreeNode node = new TreeNode();
      node = temp.Tree.rootnode; 
      int d = temp.trarray.length;
      while(node.left != null){
        if(j < d/2){
          node = node.left;
          d = d/2;         
        }
        else{
          node = node.right;
          j = j - d/2;
          d =d/2;
        }      
      }
     
      TreeNode node2 = node;
     // first list computing
      while(node.parent != null){
       
        if(node.parent.left == node){
          Pair<String, String> p1 = new Pair<String, String>("0","0");
          p1.first = node.val;
          p1.second = node.parent.right.val;
          pair.first.add(p1);
        }
        else{
            Pair<String, String> p1 = new Pair<String, String>("0","0");
          p1.second = node.val;
          p1.first = node.parent.left.val;
          pair.first.add(p1);
        }
        node = node.parent;


      }

     
      Pair<String, String> p1 = new Pair<String, String>("0","0");
      p1.second = null;
      p1.first = node.val;
      pair.first.add(p1);
     // updating my coins
     
      TransactionBlock n = temp;
      Pair<String, TransactionBlock> pair1 = new Pair<String, TransactionBlock>("0", temp);
      pair1.first = tobj.coinID;
      pair1.second = temp;
      for(int i =0; i < tobj.Destination.mycoins.size(); i++){
        if(Integer.parseInt(tobj.Destination.mycoins.get(i).first) > Integer.parseInt(tobj.coinID)){
          tobj.Destination.mycoins.add(i,pair1);
          break;
        }
      }
      // computing second list of pair
      
      List<Pair<String, String>> list = new ArrayList<Pair<String, String>>();
      TransactionBlock temp2 = DSObj.bChain.lastBlock;
      while(temp2 != temp.previous){
       
        Pair<String, String> p3 = new Pair<String, String>("0","0");
        p3.first = temp2.dgst;
        p3.second = temp2.previous.dgst + "#" + temp2.trsummary + "#" + temp2.nonce;
        list.add(p3);
        temp2 = temp2.previous;
      }
      if(temp.previous == null){
        Pair<String, String> p3 = new Pair<String, String>("0", "0");
        p3.first = null;
        p3.second = null;
        list.add(p3);

      }
      else{
      Pair<String, String> p3 = new Pair<String, String>("0", "0");
      p3.first = temp2.dgst;
      p3.second = null;
      list.add(p3);
      }
      // reversing the 2nd list

      List<Pair<String, String>> list2 = new ArrayList<Pair<String, String>>();
      for(int i = list.size()-1; i >= 0; i--){
        list2.add(list.get(i));
      }     
      
      pair.second = list2;
    

      int i =0;
      int k =0;
     
      boolean found = false;

     
           
      while(!found){
       
        if(in_process_trans[i] == tobj){
          found = true;
          k = i;
        }
        i++;
      }
     
      i = 0;
      int c = 0;
      Transaction[] process = new Transaction[in_process_trans.length-1];
     

      
      while(i < in_process_trans.length-1){     
        if(c == k){
         
          c++;                   
        }
        else{
          process[i] = in_process_trans[c];
          c++;
          i++;
        }       
      }
      in_process_trans = process;
    }
    else{
      throw new MissingTransactionException();
    }
    return pair;   
  }
  
  public Pair<List<Pair<String, String>>, List<Pair<String, String>>> finalizeCoinsend (Transaction tobj, DSCoin_Malicious DSObj) throws MissingTransactionException {
    // checking whether tobj exist or not
    boolean check = false;
    TransactionBlock temp =  DSObj.bChain.FindLongestValidChain();
    TransactionBlock temp_2 = DSObj.bChain.FindLongestValidChain();
    
    Transaction trans = new Transaction();
    int j =0;
    while(temp_2 != null && !check){
      for(int i =0; i < temp_2.trarray.length; i++){
        if(tobj == temp_2.trarray[i]){
          trans = tobj;
          j = i;
          check = true;
          temp = temp_2;      
          break;
        }
      }
      if(check)
      break;
      temp_2 = temp_2.previous;
    }

   

    List<Pair<String, String>> l = new ArrayList<Pair<String, String>>();
    
    Pair<List<Pair<String, String>>, List<Pair<String, String>>> pair = new  Pair<List<Pair<String, String>>, List<Pair<String, String>>>(l,l); 
   
    if(check){
      
      TreeNode node = new TreeNode();
      node = temp.Tree.rootnode; 
      int d = temp.trarray.length;
      while(node.left != null){
        if(j < d/2){
          node = node.left;
          d = d/2;         
        }
        else{
          node = node.right;
          j = j - d/2;
          d =d/2;
        }      
      }
      
      TreeNode node2 = node;
     
      while(node.parent != null){
        
        if(node.parent.left == node){
          Pair<String, String> p1 = new Pair<String, String>("0","0");
          p1.first = node.val;
          p1.second = node.parent.right.val;
          pair.first.add(p1);
        }
        else{
            Pair<String, String> p1 = new Pair<String, String>("0","0");
          p1.second = node.val;
          p1.first = node.parent.left.val;
          pair.first.add(p1);
        }
        node = node.parent;


      }
      
      Pair<String, String> p1 = new Pair<String, String>("0","0");
      p1.second = null;
      p1.first = node.val;
      pair.first.add(p1);

     
      TransactionBlock n = temp;
      Pair<String, TransactionBlock> pair1 = new Pair<String, TransactionBlock>("0", temp);
      pair1.first = tobj.coinID;
      pair1.second = temp;
      for(int i =0; i < tobj.Destination.mycoins.size(); i++){
        if(Integer.parseInt(tobj.Destination.mycoins.get(i).first) > Integer.parseInt(tobj.coinID)){
          tobj.Destination.mycoins.add(i,pair1);
          break;
        }
      }
      
      List<Pair<String, String>> list = new ArrayList<Pair<String, String>>();
      TransactionBlock temp2 = DSObj.bChain.FindLongestValidChain();
      while(temp2 != temp.previous){
       
        Pair<String, String> p3 = new Pair<String, String>("0","0");
        p3.first = temp2.dgst;
        p3.second = temp2.previous.dgst + "#" + temp2.trsummary + "#" + temp2.nonce;
        list.add(p3);
        temp2 = temp2.previous;
      }
      if(temp.previous == null){
        Pair<String, String> p3 = new Pair<String, String>("0", "0");
        p3.first = null;
        p3.second = null;
        list.add(p3);

      }
      else{
      Pair<String, String> p3 = new Pair<String, String>("0", "0");
      p3.first = temp2.dgst;
      p3.second = null;
      list.add(p3);
      }

      List<Pair<String, String>> list2 = new ArrayList<Pair<String, String>>();
      for(int i = list.size()-1; i >= 0; i--){
        list2.add(list.get(i));
      }     
      
      pair.second = list2;
    

      int i =0;
      int k =0;
     

      boolean found = false;

     
           
      while(!found){
       
        if(in_process_trans[i] == tobj){
          found = true;
          k = i;
        }
        i++;
      }
      
      i = 0;
      int c = 0;
      Transaction[] process = new Transaction[in_process_trans.length-1];
     

      
      while(i < in_process_trans.length-1){     
        if(c == k){
          
          c++;                   
        }
        else{
          process[i] = in_process_trans[c];
          c++;
          i++;
        }       
      }
      in_process_trans = process;
    }
    else{
      throw new MissingTransactionException();
    }
    return pair;   
  }


  public void MineCoin(DSCoin_Honest DSObj) {
    int i = 0;
    int l = 0;
    Transaction[] arr= new Transaction[DSObj.bChain.tr_count];
    
    // removing valid transactions from pending transactions
    while(i < DSObj.bChain.tr_count - 1 && l < DSObj.pendingTransactions.size()){
      boolean found = false;
      if(l>0){
      for(int j =l-1; j >= 0; j--){        
        if(DSObj.pendingTransactions.get(l).coinID.equals(DSObj.pendingTransactions.get(j).coinID)){
          found = true;
        }
      }  
    }
    else{
      found = false;
    } 
   
    
    
      if(!found && special_check_1(DSObj.pendingTransactions.get(l), DSObj)){
       
        arr[i] = DSObj.pendingTransactions.get(l);
        i++;       
      }   
     l++;     
    }
   
    


   
    Transaction[] arr1 = new Transaction[DSObj.pendingTransactions.size() - l];
   
    // reward transaction

    arr[i] = new Transaction();
    DSObj.latestCoinID = Integer.toString(Integer.parseInt(DSObj.latestCoinID) + 1);
    arr[i].coinID = DSObj.latestCoinID;
    arr[i].Source = null;
    arr[i].Destination = this;
    arr[i].coinsrc_block = null;

   

    // updating pending transactions

    int count_1 =0;
    for(int i_1 = l; i_1 < DSObj.pendingTransactions.size(); i_1++){
     
      arr1[count_1] = DSObj.pendingTransactions.get(i_1);
      count_1++;
    }
    DSObj.pendingTransactions = new TransactionQueue();
    for(int y =0; y < arr1.length; y++){
      DSObj.pendingTransactions.AddTransactions(arr1[y]);

    }
    // inserting block
  
    TransactionBlock tB = new TransactionBlock(arr);
    
    DSObj.bChain.InsertBlock_Honest(tB);
    Pair<String, TransactionBlock> p = new Pair<String, TransactionBlock>("0", DSObj.bChain.lastBlock);
    p.first = DSObj.bChain.lastBlock.trarray[DSObj.bChain.lastBlock.trarray.length - 1].coinID;
    p.second = DSObj.bChain.lastBlock;
    // mining reward coin
    mycoins.add(p);

   

    return;

  }  

  public void MineCoin(DSCoin_Malicious DSObj) {
    int i = 0;
    int l = 0;
    Transaction[] arr= new Transaction[DSObj.bChain.tr_count];
    while(i < DSObj.bChain.tr_count - 1 && l < DSObj.pendingTransactions.size()){
      boolean found = false;
      if(l>0){
      for(int j =l-1; j >= 0; j--){        
        if(DSObj.pendingTransactions.get(l).coinID.equals(DSObj.pendingTransactions.get(j).coinID)){
          found = true;
        }
      }  
    }
    else{
      found = false;
    }    
   
      if(!found && special_check_2(DSObj.pendingTransactions.get(l), DSObj)){
        arr[i] = DSObj.pendingTransactions.get(l);
        i++;       
      }   
     l++;     
    }  
 
   
    Transaction[] arr1 = new Transaction[DSObj.pendingTransactions.size() - l];
    arr[i] = new Transaction();
    // updating latest coin id
    DSObj.latestCoinID = Integer.toString(Integer.parseInt(DSObj.latestCoinID) + 1);
    arr[i].coinID = DSObj.latestCoinID;
    arr[i].Source = null;
    arr[i].Destination = this;
    arr[i].coinsrc_block = null;
    int count_1 =0;
    for(int i_1 = l; i_1 < DSObj.pendingTransactions.size(); i_1++){
      arr1[count_1] = DSObj.pendingTransactions.get(i_1);
      count_1++;
    }
    DSObj.pendingTransactions = new TransactionQueue();
    for(int y =0; y < arr1.length; y++){
      DSObj.pendingTransactions.AddTransactions(arr1[y]);

    }
   
    TransactionBlock tB = new TransactionBlock(arr);  
    DSObj.bChain.InsertBlock_Malicious(tB);
    Pair<String, TransactionBlock> p = new Pair<String, TransactionBlock>("0", DSObj.bChain.FindLongestValidChain());
    p.first = DSObj.bChain.FindLongestValidChain().trarray[DSObj.bChain.FindLongestValidChain().trarray.length - 1].coinID;
    p.second = DSObj.bChain.FindLongestValidChain();
    mycoins.add(p);
   
    return; 
  } 
  // this method checks whether a transaction is valid from last block to source block
  public boolean special_check_1(Transaction t, DSCoin_Honest DSObj){
    if(t.coinsrc_block == null){
      boolean valid = true;
     
     
      return valid;  


    }
    else{
      boolean valid = false;
      int n = t.coinsrc_block.trarray.length;
      for(int i = 0; i < n; i++) {
        if(t.coinID.equals(t.coinsrc_block.trarray[i].coinID) && t.Source == (t.coinsrc_block.trarray[i].Destination)){
        
          valid = true;
        }  
      }

      TransactionBlock temp =  DSObj.bChain.lastBlock;
      
      while(temp != t.coinsrc_block){
        int n_2 = temp.trarray.length;
        for(int i = 0; i < n_2; i++) {
          if(t.coinID.equals(temp.trarray[i].coinID) && t.Source.UID.equals(temp.trarray[i].Destination)){
            valid = false;
          }
        }
        
        temp = temp.previous;
      }

      return valid;

    }

   
 



   
  }

  public boolean special_check_2(Transaction t, DSCoin_Malicious DSObj){
    if(t.coinsrc_block == null){
      boolean valid = true;
    
  
      return valid;  


    }
    else{
      boolean valid = false;
      int n = t.coinsrc_block.trarray.length;
      for(int i = 0; i < n; i++) {
        if(t.coinID.equals(t.coinsrc_block.trarray[i].coinID) && t.Source == (t.coinsrc_block.trarray[i].Destination)){
          valid = true;
        }  
      }

      TransactionBlock temp = DSObj.bChain.FindLongestValidChain();
    
      while(temp != t.coinsrc_block){
        n = temp.trarray.length;
        for(int i = 0; i < n; i++) {
          if(t.coinID.equals(temp.trarray[i].coinID) ){
            valid = false;
          }
        }
        
        temp = temp.previous;
      }

      return valid;
    }


    
  }

}
