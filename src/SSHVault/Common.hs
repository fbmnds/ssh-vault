
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE CPP #-}
--{-# LANGUAGE PackageImports -#}

module SSHVault.Common
  ( encryptAES
  , decryptAES
  , genAESKey
  , genSHA256
  , getAESMasterKeyU
  , procEC
  , procD
  , shellD
  , execSSH
  , execExp
  , rand1000
  , randS
  , chmodF
  , chmodD
  , chmodD_R
  , take2nd
  , split4
  , substring
  , prefix
  , getUTC
  , ssh_add
  )

where

import           SSHVault.SBytes
import qualified SSHVault.Vault.Config as Cfg

import Data.List (intercalate)
--import qualified Data.Text as T
--import qualified Data.ByteString as B
--import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteArray as BA
--import qualified Data.ByteString.UTF8 as CU
--import           Data.Binary (decode)
import Data.Time.Clock as Clock

import qualified Crypto.Simple.CTR as CTR
import           Crypto.Hash (hash, SHA256 (..), Digest)

import           Control.Exception (SomeException, catch)
import           Control.Monad (when)
import           System.IO
import           System.Random
import           System.Process
import           System.Exit (ExitCode(..))

import qualified Turtle.Prelude as Tu
import qualified Turtle as Tu
import           Turtle.Format

-- import Foreign
-- import Foreign.C.Types
import Foreign.C.String

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
randS n = take n . stripChars ":;<=>?@[\\]^_`" . randomRs ('0','z') <$> newStdGen


encryptAES :: ToSBytes a => AESMasterKey -> a -> IO BA.ScrubbedBytes
encryptAES key msg = do
    c' <- CTR.encrypt (toBytes key) (toBytes msg)
    return $ toSBytes c'


decryptAES :: ToSBytes a => AESMasterKey -> a -> IO BA.ScrubbedBytes
decryptAES key cipher = do
    c' <- CTR.decrypt (toBytes key) (toBytes cipher)
    return $ toSBytes c'

genSHA256 :: ToSBytes a => a -> String
genSHA256 key =
    let h :: Digest SHA256
        h = hash $ toBytes key in
    show h

-- | GOAL keep vault password (MasterKey)
--   and its 32 byte representation for AES256 (AESMasterKey)
--   in ScrubbedBytes throughout the app
genAESKey :: MasterKey -> AESMasterKey
genAESKey key = toAESMasterKey . take2nd . genSHA256 $ toSBytes key


getAESMasterKeyU :: IO AESMasterKey
getAESMasterKeyU = do
    old <- hGetEcho stdin
    putStr "Vault password: "
    hFlush stdout
    hSetEcho stdin False
    keyPhrase <- getLine -- TODO vault password passes IO in plain text
                         -- IDEA use pointer to overwrite after use
                         -- https://stackoverflow.com/questions/46743945/how-to-create-a-ptr-word8-for-bytestring?rq=1
    when (length keyPhrase < 12) $ error "Vault password too short."
    putChar '\n'
    hFlush stdout
    hSetEcho stdin old
    return . genAESKey $ toMasterKey keyPhrase


procEC :: String -> IO (ExitCode, String, String)
procEC cmd = readCreateProcessWithExitCode (shell cmd) []

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

chmodF :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodF m fn = procD ("chmod" :: Tu.Text) [toText m, toText fn]

chmodD :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodD m fn = procD ("chmod" :: Tu.Text) [toText m, toText fn]

chmodD_R :: (ToSBytes a, ToSBytes b) => a -> b -> IO ()
chmodD_R m fn = procD ("chmod" :: Tu.Text) ["-R", toText m, toText fn]


execSSH :: KeyPhrase -> String -> IO ()
execSSH ph sp = catch
    (readCreateProcess (shell cmd) [] >>= putStr)
    (\ (_ :: SomeException) -> do
        putStrLn ("could not execute expect script" :: String)
        error "exit")
    where
        (cmd :: String) = "bash -c \"expect << EOF\n"
         ++ "spawn " ++ sp ++ "\n"
         ++ "expect \\\"Enter passphrase\\\"\n"
         ++ "send \\\"" ++ toString ph ++ "\\r\\\"\n"
         ++ "expect eof\n"
         ++ "EOF\""


execExp :: Cfg.Config -> String -> [String] -> IO ()
execExp _ exp' ls = do
        r3 <- rand1000 3
        let fn = "/dev/shm/" ++ exp' ++ "-" ++ intercalate "-" (map show r3) ++ ".exp"
        catch ( do
            _ <- procD "touch" [fn]
            _ <- chmodF ("600" :: String) fn
            _ <- writeFile fn (intercalate "\n" ls)
            _ <- procD "expect" ["-f", fn]
            _ <- procD "rm" [fn]
            return () )
            (\ (_ :: SomeException) -> procD "rm" [fn] )

    -- TODO procD "expect" ["-f", fn] succeeds, but throws exception


foreign import ccall "ssh_add.h"
    ssh_add :: CString
            -> CString
            -> CString
            -> CString
            -> Int

{-

foreign import ccall "fork_exec_with_pty.h"
    fork_exec_with_pty :: Int
                       -> Int
                       -> CInt
                       -> CString
                       -> Ptr CString
                       -> Ptr CString
                       -> Ptr Int
                       -> IO Fd

fork_exec_with_pty
    ( HsInt sx
    , HsInt sy
    , int search
    , const char *file
    , char *const argv[]
    , char *const env[]
    , HsInt *child_pid
)
-}