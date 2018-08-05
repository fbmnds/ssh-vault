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
  , execExp
  , rand1000
  , randS
  , chmodFile
  , chmodDir
  , chmodDirR
  , take2nd
  , split4
  , substring
  , prefix
  , getUTC
  )

where

import           SSHVault.SBytes
import qualified SSHVault.Vault.Config as Cfg

import Data.List (intercalate)
import qualified Data.Text as T
import qualified Data.ByteString as B
--import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteArray as BA
import qualified Data.ByteString.UTF8 as CU
--import           Data.Binary (decode)
import Data.Time.Clock as Clock

import qualified Crypto.Simple.CTR as CTR
import           Crypto.Hash (hash, SHA256 (..), Digest)

--import           Control.Exception (bracket_)
import           System.IO
import           System.Random

import qualified Turtle.Prelude as Tu
import qualified Turtle as Tu
import           Turtle.Format



getUTC :: IO String
getUTC = show <$> Clock.getCurrentTime


take2nd :: [a] -> [a]
take2nd (_ : _ : x' : y' : xs') = x' : y' : take2nd xs'
take2nd _ = []

split4 :: String -> String
split4 [w', x', y', z']  = [w', x', y', z']
split4 (w' : x' : y' : z' : xs') = w': x' : y' : z': '-' : split4 xs'
split4 _ = []

substring :: String -> String -> Bool
substring (_:_) [] = False
substring xs ys
    | prefix xs ys = True
    | substring xs (tail ys) = True
    | otherwise = False

prefix :: String -> String -> Bool
prefix [] _ = True
prefix _ [] = False
prefix (x':xs) (y:ys) = (x' == y) && prefix xs ys


stripChars :: String -> String -> String
stripChars = filter . flip notElem

rand1000 :: Int -> IO [Int]
rand1000 n = take n . randomRs (0, 999) <$> newStdGen

randS :: Int -> IO String
randS n = take n . stripChars "$\\\"'{}`" . randomRs (' ','~') <$> newStdGen


encryptAES :: ToSBytes a => BA.ScrubbedBytes -> a -> IO BA.ScrubbedBytes
-- CU.ByteString -> CU.ByteString -> IO CU.ByteString
encryptAES key msg = do
  c' <- CTR.encrypt (toBytes key) (toBytes msg)
  return $ toSBytes c'


decryptAES :: ToSBytes a => BA.ScrubbedBytes -> a -> IO BA.ScrubbedBytes
-- CU.ByteString -> CU.ByteString -> IO CU.ByteString
decryptAES key cipher = do
  c' <- CTR.decrypt (toBytes key) (toBytes cipher)
  return $ toSBytes c'

genSHA256 :: T.Text -> String
genSHA256 key =
  let h :: Digest SHA256
      h = hash $ toBytes key in
  show h

genAESKey :: T.Text -> BA.ScrubbedBytes
genAESKey key = toSBytes . take2nd $ genSHA256 key


getKeyPhrase :: IO BA.ScrubbedBytes
getKeyPhrase = do
  old <- hGetEcho stdin
  putStr "Vault password: "
  hFlush stdout
  hSetEcho stdin False
  keyPhrase <- getLine
  putChar '\n'
  hFlush stdout
  hSetEcho stdin old
  return . genAESKey $ toText keyPhrase


procD :: ToSBytes a => a -> [a] -> IO ()
procD a b = do
    ec <- Tu.proc (toText a) (map toText b) Tu.empty
    case ec of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s % w %s) "failed to execute: " (toText a) (map toText b) "\n"
        _ -> return ()

shellD :: ToSBytes a => a -> IO ()
shellD a = do
    ec <- Tu.shell (toText a) Tu.empty
    case ec of
        Tu.ExitFailure _ -> Tu.die $ Tu.format (s % s %s) "failed to execute: " (toText a) "\n"
        _ -> return ()

chmodFile :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodFile m fn = procD ("chmod" :: Tu.Text) [toText m, toText fn]

chmodDir :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodDir m fn = procD ("chmod" :: Tu.Text) [toText m, toText fn]

chmodDirR :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodDirR m fn = procD ("chmod" :: Tu.Text) ["-R", toText m, toText fn]


execExp :: Cfg.Config -> String -> [String] -> IO ()
execExp cfg exp' ls = do
  r3 <- rand1000 3
  let fn = Cfg.dir cfg ++ "/" ++ exp' ++ "-" ++ intercalate "-" (map show r3) ++ ".exp"
  _ <- procD "touch" [fn]
  _ <- chmodFile ("600" :: String) fn
  _ <- writeFile fn (intercalate "\n" ls)
  _ <- procD "expect" ["-f", fn]
  _ <- procD "rm" [fn]
  return ()
