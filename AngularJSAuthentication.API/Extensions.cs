using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AngularJSAuthentication.API
{
    /// <summary>
    ///     <see cref="List{T}"/> helper extentions.
    /// </summary>
    public static class IdentityUserClaimListExtensions
    {
        /// <summary>
        /// Searching the <paramref name="source"/> claims for a specific claim that matches the passed <paramref name="predicate"/> and 
        /// adds it to the list if is found.
        /// </summary>
        /// <param name="list">The list.</param>
        /// <param name="source">The source.</param>
        /// <param name="predicate">The predicate.</param>
        /// <param name="userId">The username.</param>
        public static void TryAddClaim(this ICollection<IdentityUserClaim> list, List<Claim> source, Func<Claim, bool> predicate, string userId)
        {
            Claim tmp = source.FirstOrDefault(predicate);
            if (tmp != null)
                list.Add(new IdentityUserClaim
                {
                    ClaimType = tmp.Type,
                    ClaimValue = tmp.Value,
                    UserId = userId
                });
        }

        public static string TryGetClaimValue(this ICollection<IdentityUserClaim> list, Func<IdentityUserClaim, bool> predicate)
        {
            var tmp = list.FirstOrDefault(predicate);
            return tmp != null ? tmp.ClaimValue : null;
        }


        public static ICollection<Claim> ToClaimsList(this ICollection<IdentityUserClaim> list, ClaimsIdentity identity)
        {
            var claims = list.Select(x => new Claim(x.ClaimType, x.ClaimValue, null, null, null, identity)).ToList();
            return claims;
        }
        // provider-specific extensions:

        //public static ICollection<string> GetGyldendalProducts(this ICollection<IdentityUserClaim> userClaims)
        //{
        //    var claim = userClaims.FirstOrDefault(x => x.ClaimType == Constants.ClaimTypes.GyldendalProducts) ??
        //                userClaims.FirstOrDefault(x => x.ClaimType == Constants.ClaimTypes.UniLoginProducts);

        //    Collection<string> list = null;
        //    if (claim != null)
        //        list = new Collection<string>(claim.ClaimValue.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
        //    return list ?? new Collection<string>();
        //}

        //public static string GetUniLoginGrade(this ICollection<IdentityUserClaim> userClaims)
        //{
        //    return userClaims.TryGetClaimValue(x => x.ClaimType == Constants.ClaimTypes.UniLogin.Klassetrin);
        //}

        //public static string GetUniLoginFunctionalMark(this ICollection<IdentityUserClaim> userClaims)
        //{
        //    return userClaims.TryGetClaimValue(x => x.ClaimType == Constants.ClaimTypes.UniLogin.Funktionsmarkering);
        //}
    }
}