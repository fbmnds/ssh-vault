{-# LANGUAGE OverloadedStrings #-}
--{-# LANGUAGE PackageImports -#}
module SSHVault.Common
  ( encryptAES
  , decryptAES
  , genAESKey
  , genSHA256
  , getKeyPhrase
  , procD
  , shellD
  , rand1000
  , randS
  , chmodFile
  , take2nd
  , split4
  )

where

import           SSHVault.SBytes

import qualified Data.Text as T
import qualified Data.ByteString as B
--import qualified Data.ByteString.Lazy as BL
--import qualified Data.ByteArray as BA
import qualified Data.ByteString.UTF8 as CU
--import           Data.Binary (decode)

import qualified Crypto.Simple.CTR as CTR
import           Crypto.Hash (hash, SHA256 (..), Digest)

--import           Control.Exception (bracket_)
import           System.IO
import           System.Random

import qualified Turtle.Prelude as Tu
import qualified Turtle as Tu
import           Turtle.Format



take2nd :: [a] -> [a]
take2nd (_ : _ : x' : y' : xs') = x' : y' : take2nd xs'
take2nd _ = []

split4 :: String -> String
split4 (w' : x' : y' : z' : [])  = w': x' : y' : z' : []
split4 (w' : x' : y' : z' : xs') = w': x' : y' : z': '-' : split4 xs'
split4 _ = []

rand1000 :: Int -> IO [Int]
rand1000 n = take n . randomRs (0, 999) <$> newStdGen

randS :: Int -> IO String
randS n = take n . randomRs (' ','~') <$> newStdGen


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
genAESKey key = toBytes . take2nd $ genSHA256 key


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


procD :: ToSBytes a => a -> [a] -> Tu.Shell Tu.Line -> IO ()
procD a b c = do
    ec <- Tu.proc (toText a) (map toText b) c
    case ec of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s % w %s) "failed to execute: " (toText a) (map toText b) "\n"
        _ -> return ()

shellD :: ToSBytes a => a -> Tu.Shell Tu.Line -> IO ()
shellD a b = do
    ec <- Tu.shell (toText a) b
    case ec of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s %s) "failed to execute: " (toText a) "\n"
        _ -> return ()

chmodFile :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodFile m fn = procD ("chmod" :: Tu.Text) [toText m, toText fn] Tu.empty
