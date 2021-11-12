import hashlib,time,rsa
#print("hello")
class Transaction:#交易格式   
    def __init__(self,sender,receiver,amounts,fee,message):
        self.sender   = sender  #發送人
        self.receiver = receiver    #收款人
        self.amounts  = amounts #數量
        self.fee      = fee #手續費
        self.message  = message #訊息
   # print("hello1")

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
        self.difficulty =   2   #目前難度
        self.block_time =   30  #出塊時間
        self.miner_rewards =   10  #挖礦獎勵
        self.block_limitation   =   32  #區塊容量
        self.chain  =   []  #區塊鏈
        self.pending_transactions = []  #等待中的交易

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
       # print("hello6")
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
      #  print("hello9")
        time_consumed = round(time.process_time() - start, 5)#花費時間 =round 小數點第5位(,5) 
        print(f"Hash found: {new_block.hash} @ difficulty {self.difficulty}, time cost: {time_consumed}s")
        self.chain.append(new_block)

    def adjust_difficulty(self):#調整哈希難度
        if len(self.chain) % self.adjust_difficulty_blocks != 1:
            return self.difficulty
        elif len(self.chain) <= self.adjust_difficulty_blocks:
            return self.difficulty
        else:
            start = self.chain[-1*self.adjust_difficulty_blocks-1].timestamp
            finish = self.chain[-1].timestamp
            average_time_consumed = round((finish - start) / (self.adjust_difficulty_blocks), 2)
            if average_time_consumed > self.block_time:
                print(f"Average block time:{average_time_consumed}s. Lower the difficulty")
                self.difficulty -= 1
            else:
                print(f"Average block time:{average_time_consumed}s. High up the difficulty")
                self.difficulty += 1

    def get_balance(self, account):#計算帳戶餘額
        balance = 0
        for block in self.chain:
            # Check miner reward
            miner = False
            if block.miner == account:
                miner = True
                balance += block.miner_rewards
            for transaction in block.transactions:
                if miner:
                    balance += transaction.fee
                if transaction.sender == account:
                    balance -= transaction.amounts
                    balance -= transaction.fee
                elif transaction.receiver == account:
                    balance += transaction.amounts
        return balance

    def verify_blockchain(self):#確認哈希值是否正確
        previous_hash = ''
        for idx,block in enumerate(self.chain):
            if self.get_hash(block, block.nonce) != block.hash:
                print("Error:Hash not matched!")
                return False
            elif previous_hash != block.previous_hash and idx:
                print("Error:Hash not matched to previous_hash")
                return False
            previous_hash = block.hash
        print("Hash correct!")
        return True

    def generate_address(self):
        #使用RSA加密法隨機產生一對公私鑰，並且轉存成pkcs1形式
        public, private = rsa.newkeys(512)
        public_key = public.save_pkcs1()
        private_key = private.save_pkcs1()
        return self.get_address_from_public(public_key), private_key

    def get_address_from_public(self, public):
        #把其中一些不必要與重複的內容過濾掉，只留下中間有意義的部分：
        address = str(public).replace('\\n','')
        address = address.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        address = address.replace("-----END RSA PUBLIC KEY-----'", '')
        address = address.replace(' ', '')
        print('Address:', address)
        return address

    def initialize_transaction(self, sender, receiver, amount, fee, message):
        #初始化一筆交易 先確定發送者的帳戶餘額是否足夠
        if self.get_balance(sender) < amount + fee:
            print("Balance not enough!")
            return False
        new_transaction = Transaction(sender, receiver, amount, fee, message)
        return new_transaction

    def sign_transaction(self, transaction, private_key):
        #透過sign_transaction簽署。
        private_key_pkcs = rsa.PrivateKey.load_pkcs1(private_key)
        transaction_str = self.transaction_to_string(transaction)
        signature = rsa.sign(transaction_str.encode('utf-8'), private_key_pkcs, 'SHA-1')
        return signature

    def add_transaction(self, transaction, signature):
        #先試著用地址反推回原本的公鑰，再用公鑰解密當初這筆交易紀錄的簽章看看，
        #如果公鑰解的開就可以代表是公鑰持有人本人所簽核的，這便是剛剛提到的"數位簽章"。
        public_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        public_key += transaction.sender
        public_key += '\n-----END RSA PUBLIC KEY-----\n'
        public_key_pkcs = rsa.PublicKey.load_pkcs1(public_key.encode('utf-8'))
        transaction_str = self.transaction_to_string(transaction)
        if transaction.fee + transaction.amounts > self.get_balance(transaction.sender):
            print("Balance not enough!")
            return False
        try:
            # 驗證發送者
            rsa.verify(transaction_str.encode('utf-8'), signature, public_key_pkcs)
            print("Authorized successfully!")
            self.pending_transactions.append(transaction)
            return True
        except Exception:
            print("RSA Verified wrong!")
            return False

    def start(self):
        #首先先為我們自己開一個地址，接著創造創世塊。然後便可以不停地
        #挖掘新區塊→調整難度→挖掘新區塊→調整難度→....周而復始，而且中間還可以發起交易！
        address, private = self.generate_address()
        self.create_genesis_block()
        while(True):
            self.mine_block(address)
            self.adjust_difficulty()

if __name__ == '__main__':
    block = BlockChain()
    # block.start()
    address, private = block.generate_address()

    block.create_genesis_block()
    block.mine_block(address)
    # Step1: initialize a transaction
    transaction = block.initialize_transaction(address, 'test123', 100, 1, 'Test')
    if transaction:
        # Step2: Sign your transaction
        signature = block.sign_transaction(transaction, private)
        # Step3: Send it to blockchain
        block.add_transaction(transaction, signature)
    block.mine_block(address)

    block.verify_blockchain()
    block.mine_block('hua')
    block.mine_block('hua')

    block.verify_blockchain()

    # print("Insert fake transaction.")
    # fake_transaction = Transaction('test123', address, 100, 1, 'Test')
    # block.chain[1].transactions.append(fake_transaction)
    # block.mine_block(address)
    # block.verify_blockchain()
# if __name__ == '__main__':
#     block = BlockChain()
#     block.create_genesis_block()
#     block.mine_block('hua')
#     block.mine_block('hua')

#     block.verify_blockchain()


