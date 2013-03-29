using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;

namespace NuGetGallery
{
    public class UserService : IUserService
    {
        private readonly ICryptographyService _cryptoService;
        private readonly IConfiguration _config;
        private readonly IEntityRepository<User> _userRepository;
        private readonly IEntityRepository<UserFollowsPackage> _followsRepository;
        private readonly IEntityRepository<PackageRegistration> _packagesRepository;

        public UserService(
            IConfiguration config,
            ICryptographyService cryptoService,
            IEntityRepository<User> userRepository,
            IEntityRepository<UserFollowsPackage> followsRepository,
            IEntityRepository<PackageRegistration> packagesRepository)
        {
            _config = config;
            _cryptoService = cryptoService;
            _userRepository = userRepository;
            _followsRepository = followsRepository;
            _packagesRepository = packagesRepository;
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

            var hashedPassword = _cryptoService.GenerateSaltedHash(password, Constants.PBKDF2HashAlgorithmId);

            var newUser = new User(
                username,
                hashedPassword)
                {
                    ApiKey = Guid.NewGuid(),
                    EmailAllowed = true,
                    UnconfirmedEmailAddress = emailAddress,
                    EmailConfirmationToken = _cryptoService.GenerateToken(),
                    PasswordHashAlgorithm = Constants.PBKDF2HashAlgorithmId,
                };

            if (!_config.ConfirmEmailAddresses)
            {
                newUser.ConfirmEmailAddress();
            }

            _userRepository.InsertOnCommit(newUser);
            _userRepository.CommitChanges();

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
                user.EmailConfirmationToken = _cryptoService.GenerateToken();
            }

            user.EmailAllowed = emailAllowed;
            _userRepository.CommitChanges();
        }

        public User FindByApiKey(Guid apiKey)
        {
            return _userRepository.GetAll().SingleOrDefault(u => u.ApiKey == apiKey);
        }

        public virtual User FindByEmailAddress(string emailAddress)
        {
            // TODO: validate input

            return _userRepository.GetAll().SingleOrDefault(u => u.EmailAddress == emailAddress);
        }

        public virtual User FindByUnconfirmedEmailAddress(string unconfirmedEmailAddress)
        {
            // TODO: validate input

            return _userRepository.GetAll().SingleOrDefault(u => u.UnconfirmedEmailAddress == unconfirmedEmailAddress);
        }

        public virtual User FindByUsername(string username)
        {
            // TODO: validate input

            return _userRepository.GetAll()
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

            if (!_cryptoService.ValidateSaltedHash(user.HashedPassword, password, user.PasswordHashAlgorithm))
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

            if (!_cryptoService.ValidateSaltedHash(user.HashedPassword, password, user.PasswordHashAlgorithm))
            {
                return null;
            }
            
            if (!user.PasswordHashAlgorithm.Equals(Constants.PBKDF2HashAlgorithmId, StringComparison.OrdinalIgnoreCase))
            {
                // If the user can be authenticated and they are using an older password algorithm, migrate them to the current one.
                ChangePasswordInternal(user, password);
                _userRepository.CommitChanges();
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
            _userRepository.CommitChanges();
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
            _userRepository.CommitChanges();
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

            _userRepository.CommitChanges();
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

            user.PasswordResetToken = _cryptoService.GenerateToken();
            user.PasswordResetTokenExpirationDate = DateTime.UtcNow.AddMinutes(tokenExpirationMinutes);

            _userRepository.CommitChanges();
            return user;
        }

        public bool ResetPasswordWithToken(string username, string token, string newPassword)
        {
            if (String.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentNullException("newPassword");
            }

            var user = (from u in _userRepository.GetAll()
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
                _userRepository.CommitChanges();
                return true;
            }

            return false;
        }

        private void ChangePasswordInternal(User user, string newPassword)
        {
            var hashedPassword = _cryptoService.GenerateSaltedHash(newPassword, Constants.PBKDF2HashAlgorithmId);
            user.PasswordHashAlgorithm = Constants.PBKDF2HashAlgorithmId;
            user.HashedPassword = hashedPassword;
        }

        public void Follow(User user, PackageRegistration package, bool saveChanges)
        {
            UserFollowsPackage follow = _followsRepository.GetAll()
                .FirstOrDefault(ufp => ufp.UserKey == user.Key && ufp.PackageRegistrationKey == package.Key);

            if (follow == null)
            {
                follow = UserFollowsPackage.Create(user, package);
                _followsRepository.InsertOnCommit(follow);
            }

            follow.IsFollowed = true;
            follow.LastModified = DateTime.UtcNow;

            if (saveChanges)
            {
                _followsRepository.CommitChanges();
            }
        }

        public void Unfollow(User user, PackageRegistration package, bool saveChanges)
        {
            UserFollowsPackage follow = _followsRepository.GetAll()
                .FirstOrDefault(ufp => ufp.UserKey == user.Key && ufp.PackageRegistrationKey == package.Key);

            if (follow == null)
            {
                return; // unfollowing something you never followed is a no-op 
            }

            follow.IsFollowed = false;
            follow.LastModified = DateTime.UtcNow;

            if (saveChanges)
            {
                _followsRepository.CommitChanges();
            }
        }

        public bool IsFollowing(User user, PackageRegistration package)
        {
            var userFollowPackage = _followsRepository.GetAll()
                .FirstOrDefault(ufp => ufp.UserKey == user.Key && ufp.PackageRegistrationKey == package.Key);

            if (userFollowPackage == null)
            {
                return false;
            }

            return userFollowPackage.IsFollowed;
        }

        public IEnumerable<string> GetFollowedPackageIdsInSet(User user, IEnumerable<string> packageIds)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            var packageIdSet = packageIds.ToArray();

            var followedIds = _followsRepository
                .GetAll()
                .Include(ufp => ufp.PackageRegistration)
                .Where(
                    ufp => ufp.UserKey == user.Key && 
                    ufp.IsFollowed &&
                    packageIdSet.Contains(ufp.PackageRegistration.Id))
                .Select(ufp => ufp.PackageRegistration.Id);

            return followedIds.ToList();
        }

        public IQueryable<UserFollowsPackage> GetFollowedPackages(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            return _followsRepository.GetAll()
                .Where(ufp => ufp.UserKey == user.Key);
        }
    }
}