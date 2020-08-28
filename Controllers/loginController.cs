using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace loginApi.Controllers
{

    public class loginController : ControllerBase
    {
        /*** DB Connection ***/
        // static string dbCon = "Server=tcp:95.217.206.195,1433;Initial Catalog=FAR;Persist Security Info=False;User ID=sa;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";        
        // static string dbCon = "Server=tcp:95.217.206.195,1433;Initial Catalog=FAR;Persist Security Info=False;User ID=sa;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";

        // live server
        // static string dbCon = "Server=tcp:58.27.164.136,1433;Initial Catalog=FAR;Persist Security Info=False;User ID=far;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";
        // static string dbCon = "Server=tcp:125.1.1.244,1433;Initial Catalog=FAR;Persist Security Info=False;User ID=far;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";
        static string dbCon = "Server=tcp:10.1.1.1,1433;Initial Catalog=FAR;Persist Security Info=False;User ID=far;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";

        // Production Database
        // static string dbCon = "Server=tcp:58.27.164.136,1433;Initial Catalog=FARProd;Persist Security Info=False;User ID=far;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";
        // static string dbCon = "Server=tcp:125.1.1.244,1433;Initial Catalog=FARProd;Persist Security Info=False;User ID=far;Password=telephone@123;MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=True;Connection Timeout=30;";


        private IConfiguration _config;

        public loginController(IConfiguration config)
        {
            _config = config;
        }





        /*** Create Token for Handling Frontend session call ***/
        [AllowAnonymous]
        [HttpPost]
        [EnableCors("CorePolicy")]
        [Route("api/CreateToken")]
        public IActionResult CreateToken([FromBody] login obj)
        {
            //* Try Block
            try
            {

                //* Declaration
                IActionResult response = Unauthorized();
                List<userDetail> rows = new List<userDetail>();
                var verificationMsg = Authenticate(obj);

                //* Checking if data in user variable is empty
                if (verificationMsg == "Success")
                {
                    var tokenString = BuildToken();

                    //* Database Query and result assigned to declared list
                    using (IDbConnection con = new SqlConnection(dbCon))
                    {

                        //var query = @"SELECT ID, LoginName, ispincode as PinStatus FROM dbo.Users
                        //              WHERE LoginName= '" + obj.UserName + "'";

                        var query = @"SELECT dbo.Users.ID, dbo.Users.LoginName, dbo.Users.IsPIncode AS PinStatus, dbo.Roles.RoleDisplayName
                                      FROM dbo.Users INNER JOIN dbo.UsersRoles ON dbo.Users.ID = dbo.UsersRoles.UserID INNER JOIN dbo.Roles ON dbo.UsersRoles.RoleID = dbo.Roles.RoleID
                                      WHERE LoginName= '" + obj.UserName + "'";


                        rows = con.Query<userDetail>(query).ToList();
                    }

                    response = Ok(new
                    {
                        msg = verificationMsg,
                        token = tokenString,
                        userDetail = rows
                    });
                }
                else
                {
                    response = Ok(new { msg = verificationMsg });
                }

                return response;
            }
            //* Exception Block
            catch (Exception ex)
            {
                throw ex;
            }
        }





        /*** Creating a JWT Token ***/
        private string BuildToken()
        {
            //* Declaration
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                        _config["Jwt:Issuer"],
                        expires: DateTime.Now.AddHours(5),
                        //expires:TimeSpan.FromMinutes(1),
                        signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }





        /*** User Login Name & Password Authentication */
        private string Authenticate(login obj)
        {
            //* Declaration
            //List<login> userProfileList = new List<login>();
            int rowAffected = 0;
            string sqlResponse = "";

            ////* Database Query and result assigned to declared list
            using (IDbConnection con = new SqlConnection(dbCon))
            {
                if (con.State == ConnectionState.Closed)
                    con.Open();

                DynamicParameters parameters = new DynamicParameters();
                parameters.Add("@UserName", obj.UserName);
                parameters.Add("@HashPassword", obj.HashPassword);
                parameters.Add("@ResponseMessage", dbType: DbType.String, direction: ParameterDirection.Output, size: 5215585);

                rowAffected = con.Execute("dbo.Sp_VerifyLogin", parameters, commandType: CommandType.StoredProcedure);

                sqlResponse = parameters.Get<string>("@ResponseMessage");
            }

            return sqlResponse;

        }




    }
}