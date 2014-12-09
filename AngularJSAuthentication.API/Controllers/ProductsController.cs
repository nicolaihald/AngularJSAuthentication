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
        [Authorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            var claimsPrincipal = Request.GetRequestContext().Principal as ClaimsPrincipal;
            var name = ClaimsPrincipal.Current.Identity.Name;
            
            var productsClaim = ClaimsPrincipal.Current.Claims.FirstOrDefault(c => c.Type == "urn:ekey:products");
            var products = Product.CreateProducts();

            if (claimsPrincipal != null)
            {
                claimsPrincipal.Claims.ToList().ForEach(x => products.Add(new Product { Isbn = string.Format("{0}:{1}", x.Type, x.Value) }));
            }

            if (productsClaim != null)
            {
                var isbnList = productsClaim.Value.Split(new[] {','}, StringSplitOptions.RemoveEmptyEntries).ToList();
                isbnList.ForEach(x => products.Add(new Product {Isbn = x}));
            }

            return Ok(products);
        }
    }


    #region Helpers

    public class Product
    {
        public string Isbn { get; set; }
        public Boolean IsShipped { get; set; }

        public static List<Product> CreateProducts()
        {
            var productList = new List<Product> 
            {
                new Product {Isbn = "FAKE", IsShipped = true },                
            };

            return productList;
        }
    }

    #endregion
}
