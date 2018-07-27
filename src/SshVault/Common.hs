{-# LANGUAGE OverloadedStrings #-}
--{-# LANGUAGE PackageImports -#}
module SshVault.Common 
  (
    Config
  , VaultKeyHash
  , encryptAES
  , decryptAES
  , genAESKey
  , genSHA256
  , getKeyPhrase
  , getConfig
  , getCfgHome
  , getCfgVaultFile
  , getCfgVaultKey
  , procD 
  , shellD
  , rand1000
  , randS
  )

where

import           SshVault.SBytes

import qualified Data.Text as T
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteArray as BA
import qualified Data.ByteString.UTF8 as CU
import           Data.Binary (decode)

import qualified Crypto.Simple.CTR as CTR
import           Crypto.Hash (hash, SHA256 (..), Digest)

import           Control.Exception (bracket_)
import           System.IO
import           System.Random

import qualified Turtle.Prelude as Tu
import qualified Turtle as Tu
import           Turtle.Format

type VaultKeyHash = B.ByteString
type Config = (BA.ScrubbedBytes, Tu.FilePath, String)



rand1000 :: Int -> IO [Int]
rand1000 n = take n . randomRs (0, 999) <$> newStdGen


randS :: Int -> IO T.Text
randS n = toText . take n . randomRs (' ','~') <$> newStdGen


encryptAES :: CU.ByteString -> CU.ByteString -> IO CU.ByteString
encryptAES = CTR.encrypt


decryptAES :: CU.ByteString -> CU.ByteString -> IO CU.ByteString
decryptAES = CTR.decrypt


genSHA256 :: T.Text -> String
genSHA256 key = 
  let h :: Digest SHA256
      h = hash $ toBytes key in
  show h


genAESKey :: T.Text -> B.ByteString
genAESKey key = CU.take 32 . toBytes $ genSHA256 key


getKeyPhrase :: IO B.ByteString
getKeyPhrase = do
  old <- hGetEcho stdin
  putStr "Encryption key phrase: "
  hFlush stdout
  hSetEcho stdin False
  keyPhrase <- getLine
  putChar '\n'
  hFlush stdout
  hSetEcho stdin old
  return . genAESKey $ toText keyPhrase


getConfig :: IO Config
getConfig = do
  putStrLn "getConfig ###"
  vaultKeyHash <- getKeyPhrase
  putStrLn "getConfig"
  home <- Tu.home
  return (toSBytes vaultKeyHash, home, "/.ssh/vault")

getCfgHome :: Config -> Tu.FilePath
getCfgHome cfg = case cfg of (_,x',_) -> x'

getCfgVaultFile :: Config -> String
getCfgVaultFile cfg = case cfg of (_,h,v) -> toString $ format (fp % s) h (toText v)

getCfgVaultKey :: Config -> BA.ScrubbedBytes
getCfgVaultKey cfg = case cfg of (x,_,_) -> x


procD :: T.Text -> [T.Text] -> Tu.Shell Tu.Line -> IO ()
procD a b c = do
    e <- Tu.proc a b c
    case e of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s % w %s) "failed to execute: " a b "\n"
        _ -> return ()    


shellD :: T.Text -> Tu.Shell Tu.Line -> IO ()
shellD a b = do
    e <- Tu.shell a b
    case e of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s %s) "failed to execute: " a "\n"
        _ -> return () 

