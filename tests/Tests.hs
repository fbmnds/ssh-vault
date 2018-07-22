module Tests where

import Ssh (ssh)
import Aes256 (getVaultFile, putVaultFile)
import Turtle (printf, fromString)
import Turtle.Format
import Turtle.Prelude (stdout, input)
import Data.ByteString.Char8 (unpack)

nl :: IO ()
nl = printf s $ fromString "\n"

main :: IO () --ExitCode
main = do
  sv <- getVaultFile "/home/fb/.ssh/ssh-vault.json"
  printf s . fromString $ Data.ByteString.Char8.unpack sv
  _ <- putVaultFile "/home/fb/.ssh/ssh-vault-2.json" sv
  stdout . input $ fromString"/home/fb/.ssh/ssh-vault-2.json"
  nl