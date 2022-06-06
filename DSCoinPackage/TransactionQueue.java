package DSCoinPackage;

public class TransactionQueue {

  public Transaction firstTransaction;
  public Transaction lastTransaction;
  public int numTransactions;

  public void AddTransactions (Transaction transaction) {
    //Make a transaction object and assign it the given transaction
    
    Transaction tuple = new Transaction();
    tuple  = transaction;
    if(firstTransaction == null){
      // Checked
      firstTransaction = tuple;
      firstTransaction.next = null;
      lastTransaction = tuple;
      numTransactions = 1;
    }
    else{
      // Checked
      lastTransaction.next = tuple;
      lastTransaction = tuple;
      lastTransaction.next = null;
      numTransactions++;
    }
  }
  

  public Transaction RemoveTransaction () throws EmptyQueueException {
    Transaction tuple = firstTransaction;
    if(firstTransaction == null && firstTransaction == lastTransaction){
      // checked
      throw new EmptyQueueException();
    }
    else{   
      // checked
   firstTransaction = firstTransaction.next;
    tuple.next = null;
    numTransactions--;}
    return tuple;
  }

  public int size() {
    if(firstTransaction == null){
      return 0;
    }
    else{
      Transaction temp = new Transaction();
      temp = firstTransaction;
      int j =0;

      while(temp.next != null){
        
        temp = temp.next;
        j++;

      }

      return j+1;
    }
  }
  public Transaction get(int i) {
    Transaction temp = new Transaction();
    temp = this.firstTransaction;
    int j =0;
    if(i < this.numTransactions){
      while(i != j){
        temp = temp.next;
        j++;

      }
      return temp;
    }
    else{
      return null;
    }
  
  }
}
