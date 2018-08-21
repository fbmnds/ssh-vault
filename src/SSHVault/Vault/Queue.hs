{-# LANGUAGE ScopedTypeVariables #-}

module SSHVault.Vault.Queue
  ( Queue
  , QueueEntry (..)
  , genUserUpdateQueue
  )
  where

import SSHVault.SBytes


data QueueEntry = UserUpdate (HostName, User) | HostUpdate VaultEntry
instance Eq QueueEntry where
    (UserUpdate (h1,_)) == (UserUpdate (h2,_)) = h1       == h2
    (HostUpdate ve1)    == (HostUpdate ve2)    = host ve1 == host ve2
    (UserUpdate (h,_))  == (HostUpdate ve)     = h        == host ve
    (HostUpdate ve)     == (UserUpdate (h,_))  = host ve  == h
instance Ord QueueEntry where
    (UserUpdate (h1,_)) `compare` (UserUpdate (h2,_)) = h1       `compare` h2
    (HostUpdate ve1)    `compare` (HostUpdate ve2)    = host ve1 `compare` host ve2
    (UserUpdate (h,_))  `compare` (HostUpdate ve)     = h        `compare` host ve
    (HostUpdate ve)     `compare` (UserUpdate (h,_))  = host ve  `compare` h
type Queue = [QueueEntry]



genUserUpdateQueue :: [VaultEntry] -> [QueueEntry]
genUserUpdateQueue = concatMap
  (\ve -> (\(h, us) -> map (\u' -> UserUpdate (h, u')) us) (host ve, users ve))
