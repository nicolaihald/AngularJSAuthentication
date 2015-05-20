using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace AngularJSAuthentication.API.Controllers
{
   

    [RoutePrefix("api/products")]
    public class ProductsController : ApiController
    {

        private const bool AddAllClaimsAsProducts = true;

        [Authorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            var productsClaim = ClaimsPrincipal.Current.Claims.FirstOrDefault(c => c.Type == CustomClaimTypes.UrnGyldendalProducts);
            var products = Product.CreateProducts(productsClaim);

            if (AddAllClaimsAsProducts)
            {
                //var claimsPrincipal = Request.GetRequestContext().Principal as ClaimsPrincipal;
                products.AddFromClaimsPricipal(ClaimsPrincipal.Current);
            }

            return Ok(products);
        }
    }


    #region Helpers

    public class Product
    {
        public string Isbn { get; set; }
        public Boolean IsAuthorized { get; set; }

        public Product()
        {
            IsAuthorized = true;
        }
        public static IList<Product> CreateProducts(Claim claim)
        {
            var list = new List<Product>();
            if (claim != null)
            {
                list.Add(new Product { Isbn = string.Format("{0}:{1}", claim.Type, claim.Value) });

                var isbns = claim.Value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries).ToList();
                isbns.ForEach(x => list.Add(new Product { Isbn = x }));
            }

            return list;

        }
    }

    public static class ProductListExtensions
    {
        public static void AddFromClaimsPricipal(this IList<Product> products, ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal != null)
                claimsPrincipal.Claims.Where(x => x.Type != CustomClaimTypes.UrnGyldendalProducts).ToList().ForEach(x => products.Add(new Product { Isbn = string.Format("{0}:{1}", x.Type, x.Value) }));
        }
    }

    #endregion

    public static class CustomClaimTypes
    {
        public static string UrnGyldendalProducts = "urn:gyldendal:products";
    }

}



