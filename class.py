import hashlib,time

class Transaction:#交易格式   
    def __init__(self,sender,receiver,amounts,fee,message):
        self.sender   = sender  #發送人
        self.receiver = receiver    #收款人
        self.amounts  = amounts #數量
        self.fee      = fee #手續費
        self.message  = message #訊息

class Block:#區塊格式   
    def __init__(self,previous_hash,difficulty,miner,miner_rewards):
        self.previous_hash = previous_hash  #前區hash值
        self.hash          = '' #目前hash值
        self.difficulty    = difficulty #難度
        self.nonce         = 0 #KEY 
        self.timestamp     = int(time.time())   #時間紀錄
        self.transactions  = [] #交易紀錄
        self.miner         = miner  #礦工
        self.miner_rewards = miner_rewards  #礦工獎勵

class BlockChain:
    def __init__(self):
        self.adjust_difficulty_blocks = 10  #難度調節區塊數
        self.difficulty =   1   #目前難度
        self.block_time =   30  #出塊時間
        self.mining_rewards =   10  #挖礦獎勵
        self.block_limitation   =   32  #區塊容量
        self.chain  =   []  #區塊鏈
        self.pending_transacrions = []  #等待中的交易

    def create_genesis_block(self):#創世塊
        print("Create genesis block ")
        new_block = Block('Hello World!',1,'hua',10)    #HASH 難度 礦工 獎勵
        new_block.hash = self.get_hash(new_block,0)
        self.chain.append(new_block)

    def transaction_to_string(self, transaction):#交易明細轉換成字串
        transaction_dict ={
            'sender':str(transaction.sender),
            'receiver':str(transaction.receiver),
            'amounts':transaction.amounts,
            'fee':transaction.fee,
            'message':transaction.message
        }   
        return str(transaction_dict)

    def get_transactions_string(self,block):#負責把區塊紀錄的所有交易明細轉換成一個字串
        transaction_str = ''
        for transaction in block.transactions:
            transaction_str+=self.transaction_to_string(transaction)
        return transaction_str

    def get_hash(self,block,nonce):#負責依據這四筆資料產生相對應的哈希數
        s = hashlib.sha1()
        s.update(
            (
                block.previous_hash
                +str(block.timestamp)
                +self.get_transactions_string(block)
                +str(nonce)
            ).encode("utf-8")
        )
        h=s.hexdigest()
        return h


    def add_transaction_to_block(self, block):#放置交易紀錄至新區塊中
    # Get the transaction with highest fee by block_limitation 選擇手續費最高的幾筆交易優先加入區塊中
        self.pending_transactions.sort(key=lambda x: x.fee, reverse=True)#排序小到大
        if len(self.pending_transactions) > self.block_limitation:
            #[1:5]=從1開始到5 包含1不包含4 [0,1,2,3,4,5]=>1 2 3 
            transcation_accepted = self.pending_transactions[:self.block_limitation]# 到self.block_limitation以前的值
            self.pending_transactions = self.pending_transactions[self.block_limitation:]#從self.block_limitation到結束的值
        else:
            transcation_accepted = self.pending_transactions
            self.pending_transactions = []
        block.transactions = transcation_accepted

    def mine_block(self, miner):#挖掘新區塊
        start = time.process_time()

        last_block = self.chain[-1]
        new_block = Block(last_block.hash, self.difficulty, miner, self.miner_rewards)

        self.add_transaction_to_block(new_block)
        new_block.previous_hash = last_block.hash
        new_block.difficulty = self.difficulty
        new_block.hash = self.get_hash(new_block, new_block.nonce)

        while new_block.hash[0: self.difficulty] != '0' * self.difficulty:
            #當挖到的hash 開頭(第0位到第難度位) 有幾個0 != (難度)個0
            #繼續挖
            new_block.nonce += 1
            new_block.hash = self.get_hash(new_block, new_block.nonce)

        time_consumed = round(time.process_time() - start, 5)#花費時間 =round 小數點第5位(,5) 
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)

