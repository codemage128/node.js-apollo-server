const express = require('express');
const { ApolloServer, gql } = require('apollo-server-express');
const { Firmware, Vulnerability, AnalyzedFirmware } = require('./models');
const sqlite = require("./aa-sqlite");
const { url, sqlitedbPath, tablename } = require('./setting');
const typeDefs = gql`
    type Firmware{
      manufacturer: String
      model: String
      version: String
      product_type: String
      firmware_name:String
      firmware_hash:String
      release_date: String
      discontinued: Boolean
      download_link: String
      ident: String
    }
    type Vulnerability {
      id:ID
      cveid: String
      cvss: String
      cwe: String
      references: String
      summary: String
    }
    type issuesType{
       name: String
       warning: [String]
    }
    type AnalyzedFirmware{
      id: ID
      firmware_name: String
      firmware_hash: String
      checksum: String
      ComponentName: String
      Version: String
      vulnerabilities: [String]
      issues: [issuesType]
    }

    type getFirmwareHash {
      manufacturer:String
      model:String
      version:String
      firmware_name:String
      firmware_hash:String
      release_date:String
      discontinued: Boolean
    }
    type getLastestVersionType{
      version: String
    }
    type Query {
       getFirmwareHash(manufacturer: String!, model: String!, version: String!, apikey: String!): [getFirmwareHash]
       getVulnerabilities(cveid: String!, apikey: String!): [Vulnerability],
       getAnlyzedFirmwares(firmware_hash: String!, apikey: String!): [AnalyzedFirmware],
       getLastestVersion(apikey: String!, model: String!, manufacture: String!):[getLastestVersionType]
    }
    type Mutation {
       addFirmware(manufacturer: String!, model: String!, version: String!, product_type: String!, firmware_name:String!, firmware_hash:String!,release_data: String!, discontinued: Boolean!, download_link: String!, ident: String!): Firmware,
       addVulnerability(assetname: String!, assetversion: String!, cveid: String!, cvss: String!, cwe: String!, references: String!, summary: String!): Vulnerability,
       addAnlyzedFirmware(firmware_name: String!, firmware_hash: String!, checksum: String!, ComponentName: String!,Version: String!,vulnerabilities: String!,issues: String!): AnalyzedFirmware
    }
`;
const resolvers = {
   Query: {
     getLastestVersion: async (self, args, context, info) => {
       var apikey = args.apikey;
       var model = args.model;
       var manufacturer = args.manufacture;
       await sqlite.open(sqlitedbPath);
       var query = "select version from firmware order by release_date desc limit 1";
       var fs = require('fs');
       var flag = false;
       var result = fs.readFileSync("apiKey.txt", "binary", async (err, data) => {
           if(err){ console.log(err);}
           return await data
       });
       var is_ok = false;
       JSON.parse(result).map((i) => {
         if(apikey == i.apiKey){
           is_ok = true;
         }
       })
       if(is_ok){
         var result = await sqlite.all(query);
         await sqlite.close()
         return result;
       }else {
         return null
       }
     },
      getFirmwareHash: async (self, args, context, info) => {
         var manufacturer = args.manufacturer;
         var model = args.model;
         var version = args.version;
         var apikey = args.apikey;
         await sqlite.open(sqlitedbPath);
         var query = "select * from " + tablename + " where manufacturer = '" + manufacturer +  "' and model ='" + model + "' and version ='" + version + "';";
         var fs = require('fs');
         var flag = false;
         var result = fs.readFileSync("apiKey.txt", "binary", async (err, data) => {
             if(err){ console.log(err);}
             return await data
         });
         var is_ok = false;
         JSON.parse(result).map((i) => {
           if(apikey == i.apiKey){
             is_ok = true;
           }
         })
         if(is_ok){
           var result = await sqlite.all(query);
           await sqlite.close()
           return result;
         }else {
           return null
         }
      },
      getVulnerabilities:  async (self, args, context, info) => {
         var cveid = args.cveid;
         var apikey = args.apikey;
         var fs = require('fs');
         var flag = false;
         var result = fs.readFileSync("apiKey.txt", "binary", async (err, data) => {
             if(err){ console.log(err);}
             return await data
         });
         var is_ok = false;
         JSON.parse(result).map((i) => {
           if(apikey == i.apiKey){
             is_ok = true;
           }
         })
         if(is_ok){
           var result = await Vulnerability.find({cveid :`${cveid}`}).exec();
           return result;
         }else {
           return null
         }
      },
      getAnlyzedFirmwares: async (self, args, context, info) => {
         var firmware_hash = args.firmware_hash;
         var apikey = args.apikey;
         var fs = require('fs');
         var flag = false;
         var result = fs.readFileSync("apiKey.txt", "binary", async (err, data) => {
             if(err){ console.log(err);}
             return await data
         });
         var is_ok = false;
         JSON.parse(result).map((i) => {
           if(apikey == i.apiKey){
             is_ok = true;
           }
         })
         if(is_ok){
           var result = await AnalyzedFirmware.find({firmware_hash :`${firmware_hash}`}).exec();
           return result;
         }else {
           return null
         }
      }
   },
   Mutation: {
      // addVulnerability: async (_, args) => {
      //    try {
      //       let response = await Vulnerability.create(args);
      //       return response;
      //    } catch (e) {
      //       return e.message;
      //    }
      // },
      // addAnlyzedFirmware: async (_, args) => {
      //    try {
      //       let response = await AnalyzedFirmware.create(args);
      //       return response;
      //    } catch (e) {
      //       return e.message;
      //    }
      // }
   }
};

const server = new ApolloServer({ typeDefs, resolvers });
const app = express();
const { _port } = require('./setting');
server.applyMiddleware({ app });

app.listen({ port: _port }, () => {
   console.log(`🚀 Server ready at ${url + server.graphqlPath}`)
}
);
