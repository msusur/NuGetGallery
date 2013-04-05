﻿using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;

namespace NuGetGallery
{
    public class UserService : IUserService
    {
        public ICryptographyService Crypto { get; protected set; }
        public IConfiguration Config { get; protected set; }
        public IEntityRepository<User> UserRepository { get; protected set; }
        public IEntityRepository<UserFollowsPackage> FollowsRepository { get; protected set; }
        public IEntityRepository<PackageRegistration> PackageRegistrationRepository { get; protected set; }

        protected UserService() {}

        public UserService(
            IConfiguration config,
            ICryptographyService crypto,
            IEntityRepository<User> userRepository,
            IEntityRepository<UserFollowsPackage> followsRepository,
            IEntityRepository<PackageRegistration> packageRegistrationRepository)
        {
            Config = config;
            Crypto = crypto;
            UserRepository = userRepository;
            FollowsRepository = followsRepository;
            PackageRegistrationRepository = packageRegistrationRepository;
        }

        public virtual User Create(
            string username,
            string password,
            string emailAddress)
        {
            // TODO: validate input
            // TODO: consider encrypting email address with a public key, and having the background process that send messages have the private key to decrypt

            var existingUser = FindByUsername(username);
            if (existingUser != null)
            {
                throw new EntityException(Strings.UsernameNotAvailable, username);
            }

            existingUser = FindByEmailAddress(emailAddress);
            if (existingUser != null)
            {
                throw new EntityException(Strings.EmailAddressBeingUsed, emailAddress);
            }

            var hashedPassword = Crypto.GenerateSaltedHash(password, Constants.PBKDF2HashAlgorithmId);

            var newUser = new User(
                username,
                hashedPassword)
                {
                    ApiKey = Guid.NewGuid(),
                    EmailAllowed = true,
                    UnconfirmedEmailAddress = emailAddress,
                    EmailConfirmationToken = Crypto.GenerateToken(),
                    PasswordHashAlgorithm = Constants.PBKDF2HashAlgorithmId,
                };

            if (!Config.ConfirmEmailAddresses)
            {
                newUser.ConfirmEmailAddress();
            }

            UserRepository.InsertOnCommit(newUser);
            UserRepository.CommitChanges();

            return newUser;
        }

        public void UpdateProfile(User user, string emailAddress, bool emailAllowed)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (emailAddress != user.EmailAddress)
            {
                var existingUser = FindByEmailAddress(emailAddress);
                if (existingUser != null && existingUser.Key != user.Key)
                {
                    throw new EntityException(Strings.EmailAddressBeingUsed, emailAddress);
                }
                user.UnconfirmedEmailAddress = emailAddress;
                user.EmailConfirmationToken = Crypto.GenerateToken();
            }

            user.EmailAllowed = emailAllowed;
            UserRepository.CommitChanges();
        }

        public User FindByApiKey(Guid apiKey)
        {
            return UserRepository.GetAll().SingleOrDefault(u => u.ApiKey == apiKey);
        }

        public virtual User FindByEmailAddress(string emailAddress)
        {
            // TODO: validate input

            return UserRepository.GetAll().SingleOrDefault(u => u.EmailAddress == emailAddress);
        }

        public virtual User FindByUnconfirmedEmailAddress(string unconfirmedEmailAddress)
        {
            // TODO: validate input

            return UserRepository.GetAll().SingleOrDefault(u => u.UnconfirmedEmailAddress == unconfirmedEmailAddress);
        }

        public virtual User FindByUsername(string username)
        {
            // TODO: validate input

            return UserRepository.GetAll()
                .Include(u => u.Roles)
                .SingleOrDefault(u => u.Username == username);
        }

        public virtual User FindByUsernameAndPassword(string username, string password)
        {
            // TODO: validate input

            var user = FindByUsername(username);

            if (user == null)
            {
                return null;
            }

            if (!Crypto.ValidateSaltedHash(user.HashedPassword, password, user.PasswordHashAlgorithm))
            {
                return null;
            }

            return user;
        }

        public virtual User FindByUsernameOrEmailAddressAndPassword(string usernameOrEmail, string password)
        {
            // TODO: validate input

            var user = FindByUsername(usernameOrEmail)
                       ?? FindByEmailAddress(usernameOrEmail);

            if (user == null)
            {
                return null;
            }

            if (!Crypto.ValidateSaltedHash(user.HashedPassword, password, user.PasswordHashAlgorithm))
            {
                return null;
            }
            
            if (!user.PasswordHashAlgorithm.Equals(Constants.PBKDF2HashAlgorithmId, StringComparison.OrdinalIgnoreCase))
            {
                // If the user can be authenticated and they are using an older password algorithm, migrate them to the current one.
                ChangePasswordInternal(user, password);
                UserRepository.CommitChanges();
            }

            return user;
        }

        public string GenerateApiKey(string username)
        {
            var user = FindByUsername(username);
            if (user == null)
            {
                return null;
            }

            var newApiKey = Guid.NewGuid();
            user.ApiKey = newApiKey;
            UserRepository.CommitChanges();
            return newApiKey.ToString();
        }

        public bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            // Review: If the old password is hashed using something other than PBKDF2, we end up making an extra db call that changes the old hash password.
            // This operation is rare enough that I'm not inclined to change it.
            var user = FindByUsernameAndPassword(username, oldPassword);
            if (user == null)
            {
                return false;
            }

            ChangePasswordInternal(user, newPassword);
            UserRepository.CommitChanges();
            return true;
        }

        public bool ConfirmEmailAddress(User user, string token)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            if (String.IsNullOrEmpty(token))
            {
                throw new ArgumentNullException("token");
            }

            if (user.EmailConfirmationToken != token)
            {
                return false;
            }

            user.ConfirmEmailAddress();

            UserRepository.CommitChanges();
            return true;
        }

        public User GeneratePasswordResetToken(string usernameOrEmail, int tokenExpirationMinutes)
        {
            if (String.IsNullOrEmpty(usernameOrEmail))
            {
                throw new ArgumentNullException("usernameOrEmail");
            }
            if (tokenExpirationMinutes < 1)
            {
                throw new ArgumentException(
                    "Token expiration should give the user at least a minute to change their password", "tokenExpirationMinutes");
            }

            var user = FindByEmailAddress(usernameOrEmail);
            if (user == null)
            {
                return null;
            }

            if (!user.Confirmed)
            {
                throw new InvalidOperationException(Strings.UserIsNotYetConfirmed);
            }

            if (!String.IsNullOrEmpty(user.PasswordResetToken) && !user.PasswordResetTokenExpirationDate.IsInThePast())
            {
                return user;
            }

            user.PasswordResetToken = Crypto.GenerateToken();
            user.PasswordResetTokenExpirationDate = DateTime.UtcNow.AddMinutes(tokenExpirationMinutes);

            UserRepository.CommitChanges();
            return user;
        }

        public bool ResetPasswordWithToken(string username, string token, string newPassword)
        {
            if (String.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentNullException("newPassword");
            }

            var user = (from u in UserRepository.GetAll()
                        where u.Username == username
                        select u).FirstOrDefault();

            if (user != null && user.PasswordResetToken == token && !user.PasswordResetTokenExpirationDate.IsInThePast())
            {
                if (!user.Confirmed)
                {
                    throw new InvalidOperationException(Strings.UserIsNotYetConfirmed);
                }

                ChangePasswordInternal(user, newPassword);
                user.PasswordResetToken = null;
                user.PasswordResetTokenExpirationDate = null;
                UserRepository.CommitChanges();
                return true;
            }

            return false;
        }

        private void ChangePasswordInternal(User user, string newPassword)
        {
            var hashedPassword = Crypto.GenerateSaltedHash(newPassword, Constants.PBKDF2HashAlgorithmId);
            user.PasswordHashAlgorithm = Constants.PBKDF2HashAlgorithmId;
            user.HashedPassword = hashedPassword;
        }
        

        public void Follow(string username, string packageId, bool saveChanges)
        {
            UserFollowsPackage follow = GetFollowRelationship(username, packageId);
            if (follow == null)
            {
                var userKey = GetUserKey(username);
                var packageRegistrationKey = GetPackageRegistrationKey(packageId);
                follow = UserFollowsPackage.Create(userKey, packageRegistrationKey);
                FollowsRepository.InsertOnCommit(follow);
            }

            follow.IsFollowed = true;
            follow.LastModified = DateTime.UtcNow;

            if (saveChanges)
            {
                FollowsRepository.CommitChanges();
            }
        }

        public void Unfollow(string username, string packageId, bool saveChanges)
        {
            UserFollowsPackage follow = GetFollowRelationship(username, packageId);
            if (follow == null)
            {
                return; // unfollowing something you never followed is a no-op 
            }

            follow.IsFollowed = false;
            follow.LastModified = DateTime.UtcNow;

            if (saveChanges)
            {
                FollowsRepository.CommitChanges();
            }
        }

        public bool IsFollowing(string username, string packageId)
        {
            UserFollowsPackage follow = GetFollowRelationship(username, packageId);
            if (follow == null)
            {
                return false;
            }

            return follow.IsFollowed;
        }

        public IEnumerable<string> GetFollowedPackageIdsInSet(string username, string[] packageIds)
        {
            var user = FindByUsername(username);
            if (user == null)
            {
                throw new UserNotFoundException();
            }

            var followedIds = FollowsRepository
                .GetAll()
                .Include(ufp => ufp.PackageRegistration)
                .Where(
                    ufp => ufp.UserKey == user.Key && 
                    ufp.IsFollowed &&
                    packageIds.Contains(ufp.PackageRegistration.Id))
                .Select(ufp => ufp.PackageRegistration.Id);

            return followedIds.ToList();
        }

        public IQueryable<UserFollowsPackage> GetFollowedPackages(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return FollowsRepository.GetAll()
                .Where(ufp => ufp.UserKey == user.Key);
        }

        private UserFollowsPackage GetFollowRelationship(string username, string packageId)
        {
            int userKey = GetUserKey(username);
            int packageRegistrationKey = GetPackageRegistrationKey(packageId);
            return FollowsRepository.GetAll()
                .FirstOrDefault(ufp => ufp.UserKey == userKey && ufp.PackageRegistrationKey == packageRegistrationKey);
        }

        private int GetUserKey(string username)
        {
            var result = UserRepository.GetAll()
                .Where(u => u.Username == username)
                .Select(u => u.Key)
                .SingleOrThrow(() => new UserNotFoundException());

            return result;
        }

        private int GetPackageRegistrationKey(string packageId)
        {
            var result = PackageRegistrationRepository.GetAll()
                .Where(pr => pr.Id == packageId)
                .Select(u => u.Key)
                .SingleOrThrow(() => new PackageNotFoundException());

            return result;
        }
    }
}
