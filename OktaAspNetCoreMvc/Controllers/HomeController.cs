using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OktaAspNetCoreMvc.Models;

namespace OktaAspNetCoreMvc.Controllers
{
    using System.Collections.Generic;
    using System.IO;

    using Amazon;
    using Amazon.CognitoIdentity;
    using Amazon.CognitoIdentity.Model;
    using Amazon.Internal;
    using Amazon.Runtime;
    using Amazon.S3;
    using Amazon.SecurityToken;
    using Amazon.SecurityToken.Model;
    using Amazon.S3.Model;
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public async Task<IActionResult> GetObjectFromBucketAsync()
        {
            if (!this.HttpContext.User.Identity.IsAuthenticated)
            {
                return new OkObjectResult("you have to sign in to access AWS resources");
            }

            //use hardcoded keys and secret
            var client = new AmazonS3Client(new BasicAWSCredentials("AKIAZEXVW24V4DKFE3MS", "T0XtZznse/mwf3BLsJm02ilGQoVjnwaTVYGdMs8v"), RegionEndpoint.USEast1);
            return await this.ObjectFromBucket(client);
        }

        private async Task<IActionResult> ObjectFromBucket(IAmazonS3 s3Client)
        {
            var request = new GetObjectRequest { BucketName = "acmeonlybucket", Key = "test.jpg" };

            using (var response = await s3Client.GetObjectAsync(request))
            using (Stream responseStream = response.ResponseStream)
            using (StreamReader reader = new System.IO.StreamReader(responseStream))
            {
                var bytes = default(byte[]);
                using (var memstream = new MemoryStream())
                {
                    reader.BaseStream.CopyTo(memstream);
                    bytes = memstream.ToArray();
                }

                return this.File(bytes, "application/octet-stream", "imagefroms3.jpg");
            }
        }

        public async Task<IActionResult> AssumeRoleAsync()
        {
            if (!HttpContext.User.Identity.IsAuthenticated)
            {
                return new OkObjectResult("you have to sign in to access AWS resources");
            }

            try
            {
                var assumeRoleRequest = new AssumeRoleWithWebIdentityRequest
                {
                    RoleArn = "arn:aws:iam::628654266155:role/acme_app_access_s3",
                    RoleSessionName = "testsession",
                    WebIdentityToken = GetOktaTokenMiddleware.OktaToken,
                };

                var stsServiceClient = new AmazonSecurityTokenServiceClient(new BasicAWSCredentials("AKIAZEXVW24V4DKFE3MS", "T0XtZznse/mwf3BLsJm02ilGQoVjnwaTVYGdMs8v"), RegionEndpoint.USEast2);
                var response = await stsServiceClient.AssumeRoleWithWebIdentityAsync(assumeRoleRequest);

                //var response = await stsServiceClient.ListRoles()
                return new OkObjectResult($"key = {response.Credentials.AccessKeyId}   security = {response.Credentials.SecretAccessKey}");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }

        public async Task<IActionResult> AssumeRoleWithCognitoAsync()
        {
            if (!this.HttpContext.User.Identity.IsAuthenticated)
            {
                return new OkObjectResult("you have to sign in to access AWS resources");
            }

            try
            {
                // Initialize the Amazon Cognito credentials provider
                //CognitoAWSCredentials credentials = new CognitoAWSCredentials(
                //    "us-east-2:c6e1e652-eb33-4daa-a04e-9cb0418a92cc", // Identity pool ID
                //    RegionEndpoint.USEast2 // Region
                //);
                var credentials = new CognitoAWSCredentials(
                    accountId: "628654266155",
                    identityPoolId: "us-east-2:c6e1e652-eb33-4daa-a04e-9cb0418a92cc",
                    unAuthRoleArn: null,
                    authRoleArn: "arn:aws:iam::628654266155:role/acme_app_access_s3",
                    region:RegionEndpoint.USEast2
                    );

                credentials.AddLogin("dev-220949.okta.com", GetOktaTokenMiddleware.OktaToken);

                var creds = credentials.GetCredentials();

                var s3Client = new AmazonS3Client(credentials, RegionEndpoint.USEast2);

                return  await this.ObjectFromBucket(s3Client);

            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
      
        }


        public async Task<IActionResult> ConnectToAWSViaCognitoCredsAsync()
        {
            try
            {

                if (!this.HttpContext.User.Identity.IsAuthenticated)
                {
                    return new OkObjectResult("you have to sign in to access AWS resources");
                }


                AnonymousAWSCredentials cred = new AnonymousAWSCredentials();

                AmazonCognitoIdentityClient cognitoClient = new AmazonCognitoIdentityClient(
                    cred, 
                    RegionEndpoint.USEast2 
                );

                GetIdRequest idRequest = new GetIdRequest();
                idRequest.AccountId = "628654266155";
                idRequest.IdentityPoolId = "us-east-2:c6e1e652-eb33-4daa-a04e-9cb0418a92cc";
                var logins = new Dictionary<string, string> { { "dev-220949.okta.com/oauth2/default", GetOktaTokenMiddleware.OktaToken } };
                idRequest.Logins = logins;
                

                // The identity id is in the IdentityId parameter of the response object
                GetIdResponse idResp = await cognitoClient.GetIdAsync(idRequest);


                //GetCredentialsForIdentityRequest getCredentialsRequest =
                //    new GetCredentialsForIdentityRequest { IdentityId = idResp.IdentityId, Logins = logins };

                var temporaryCreds = await cognitoClient.GetCredentialsForIdentityAsync(idResp.IdentityId,logins);
                //var s3Client = new AmazonS3Client(temporaryCreds.Credentials, RegionEndpoint.USEast2);

                var s3Client = new AmazonS3Client(temporaryCreds.Credentials, RegionEndpoint.USEast2);

                return await this.ObjectFromBucket(s3Client);

                //var assumeRoleRequest = new AssumeRoleWithWebIdentityRequest
                //{
                //    RoleArn = "arn:aws:iam::628654266155:role/acme_empoyees_accessing_s3",
                //    RoleSessionName = "testsession",
                //    WebIdentityToken = GetOktaTokenMiddleware.OktaToken,
                //};

                //var stsServiceClient = new AmazonSecurityTokenServiceClient(temporaryCreds.Credentials, RegionEndpoint.USEast2);
                //var response = await stsServiceClient.AssumeRoleWithWebIdentityAsync(assumeRoleRequest);

                //return new OkObjectResult($" assumed role is {response.AssumedRoleUser.AssumedRoleId}");



            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }


        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
