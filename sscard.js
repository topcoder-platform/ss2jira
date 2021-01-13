const https = require('https');
const url = require('url');
const AWS = require('aws-sdk');

const ssm = new AWS.SSM();
const sstokenpromise = ssm.getParameter({
  Name: "/ss2jira/sstoken",
  WithDecryption: true // Decrypt outside the lambda function
}).promise();

module.exports.getSSFactors = async (event, context) => {
	var myurl = url.parse(event.url);
  let body = '';
  let path = myurl.pathname;
  if (myurl.search !== null) {
  	path = path + myurl.search;
  }
  const sstoken = (await sstokenpromise).Parameter.Value;
  console.log("Final path: "+ path);
	return new Promise((resolve, reject) => {
		const options = {
			hostname: myurl.hostname,
			port: 443,
			path: path,
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Token ' +sstoken
			}
		};
		console.log("path: " + options.path);
		const request = https.request(options, response => {
			console.log('statusCode:'+response.statusCode);
			response.on('data', chunk => body+= chunk);
			response.on('end', () => {
				console.log('get in end function');
				console.log(body);
		 		resolve({"statusCode": 200, "body": JSON.parse(body)});	
			});
		});
		request.on('error', (err) => {
			console.log('get in error function');
			reject(err);
		});
		request.end();
	});
};

module.exports.getSSMetadata = async (event, context) => {
  console.log(event);
  let body = '';
  const sstoken = (await sstokenpromise).Parameter.Value;
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.securityscorecard.io',
      port: 443,
      path: '/metadata/issue-types/'+ event.factorType,
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Token '+sstoken
      }
    };
    console.log("path: " + options.path);
    const request = https.request(options, response => {
      response.on('data', chunk => body+= chunk);
      response.on('end', () => {
        resolve({"statusCode": 200, "body": JSON.parse(body)});	
      });
    });
    request.on('error', (err) => {
      reject(err);
    });
    request.end();
  });
};
