'use strict';
const https = require('https');
const AWS = require('aws-sdk');

const ssm = new AWS.SSM();
const jiratokenpromise = ssm.getParameter({
  Name: "/ss2jira/jiratoken",
  WithDecryption: true // Decrypt outside the lambda function
}).promise();


module.exports.searchJiraExistingIssue = async (event, context) => {
//  console.log("I get issue_id: ");
  console.log(event);
  let body = '';
  const jiratoken = (await jiratokenpromise).Parameter.Value;
	return new Promise((resolve, reject) => {
		const options = {
			hostname: 'topcoder.atlassian.net',
			port: 443,
			path: '/rest/api/3/search',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Basic ' +jiratoken
			}
		};
		const reqbody = JSON.stringify({
		   jql : "project = VULN and \'external ID\' ~ " + event.issue.issue_id
		});
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
		console.log(reqbody);
		request.write(reqbody);
		request.end();
	});
};

const selfld = {
	host: {
		typosquat: "typosquat_domain",
		domain_missing_https: "domain"
	}
};
const reqbody = {
	fields: {
		summary: "",
		issuetype: {
			id:"10007"
		},
		    project: {
			    id: "10012"
		},
		customfield_10053: "",
		customfield_10054: "",
		customfield_10057: "",
		customfield_10051: "",
		description: {
			type:"doc",
			version:1,
			content: [
				{
					type: "paragraph",
					content: [
						{
							type:"text",
							text: "default"
						}
					]
				}
			]
		},
		customfield_10085: "",
		customfield_10160: "",
		customfield_10056: "",
		customfield_10059: "",
		customfield_10060: 0,
		customfield_10058: {
			type:"doc",
			version:1,
			content: [
				{
					type: "paragraph",
					content: [
						{
							type:"text",
							text:"default"
						}
					]
				}
			]
		},
		customfield_10061: "",
		labels: [
			"securityscorecard"
		]
	}
};

module.exports.updateJiraIssue = async (event, context) => {

  let body = null;
  const jiratoken = (await jiratokenpromise).Parameter.Value;
	return new Promise((resolve, reject) => {
		const options = {
			hostname: 'topcoder.atlassian.net',
			port: 443,
			path: '/rest/api/3/issue/'+ event.jirasearchresult.body.issues[0].key,
			method: 'PUT',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Basic ' +jiratoken
			}
		};
		console.log(options);
		reqbody.fields.summary = event.metadata.title;
		reqbody.fields.customfield_10053 = event.issue.issue_id;
		reqbody.fields.customfield_10160 = event.metadata.key;
		reqbody.fields.customfield_10054 = {value:event.metadata.severity.charAt(0).toUpperCase() + event.metadata.severity.slice(1) };
		reqbody.fields.customfield_10057 =  event.issue.first_seen_time.slice(0,10);
		reqbody.fields.customfield_10051 = event.issue.last_seen_time.slice(0,10);
		reqbody.fields.description.content[0].content[0].text = (event.issue.hasOwnProperty("vulnerability_description")) ? event.issue.vulnerability_description : event.metadata.recommendation;		reqbody.fields.customfield_10058.content[0].content[0].text = event.metadata.recommendation;
//		reqbody.fields.description.content[0].content[0].text = (event.issue.hasOwnProperty("vulnerability_description")) ? event.issue.vulnerability_description: "";
		reqbody.fields.customfield_10085 = (event.issue.hasOwnProperty("vulnerability_id")) ? event.issue.vulnerability_id: "";
		reqbody.fields.customfield_10056 = event.issue[selfld.host[event.issueTypeCode]];
		reqbody.fields.customfield_10059 = (event.issue.hasOwnProperty("connection_attributes")) ? event.issue.connection_attributes.dst_ip: "";
		reqbody.fields.customfield_10060 = (event.issue.hasOwnProperty("connection_attributes")) ? event.issue.connection_attributes.dst_port: 0;
		reqbody.fields.customfield_10061 = (event.issue.hasOwnProperty("initial_url")) ? event.issue.initial_url: "";
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
		console.log(JSON.stringify(reqbody));
		request.write(JSON.stringify(reqbody));
		request.end();
	});
};

module.exports.transitionJiraIssue = async (event, context) => {

  let body = null;
  const jiratoken = (await jiratokenpromise).Parameter.Value;
	return new Promise((resolve, reject) => {
		const options = {
			hostname: 'topcoder.atlassian.net',
			port: 443,
			path: '/rest/api/3/issue/'+ event.jirasearchresult.body.issues[0].key + '/transitions',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Basic ' +jiratoken
			}
		};
		console.log(options);
		const request = https.request(options, response => {
			console.log('statusCode:'+response.statusCode);
			response.on('data', chunk => body+= chunk);
			response.on('end', () => {

		 		resolve({"statusCode": +response.statusCode, "body": JSON.parse(body)});	
			});
		});
		request.on('error', (err) => {
			console.log('get in error function');
			reject(err);
		});
		request.write(JSON.stringify({ transition: { id: "11" } }));
		request.end();
	});
};
module.exports.createJiraIssue = async (event, context) => {

  let body = '';
  const jiratoken = (await jiratokenpromise).Parameter.Value;
	return new Promise((resolve, reject) => {
		const options = {
			hostname: 'topcoder.atlassian.net',
			port: 443,
			path: '/rest/api/3/issue',
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'Authorization': 'Basic ' +jiratoken
			}
		};
		reqbody.fields.summary = event.metadata.title;
		reqbody.fields.customfield_10053 =  event.issue.issue_id;
		reqbody.fields.customfield_10054 = {value:event.metadata.severity.charAt(0).toUpperCase() + event.metadata.severity.slice(1) };
		reqbody.fields.customfield_10057 =  event.issue.first_seen_time.slice(0,10);
		reqbody.fields.customfield_10051 = event.issue.last_seen_time.slice(0,10);
		reqbody.fields.description.content[0].content[0].text = (event.issue.hasOwnProperty("vulnerability_description")) ? event.issue.vulnerability_description : event.metadata.recommendation;
		reqbody.fields.customfield_10058.content[0].content[0].text = event.metadata.recommendation;
//		reqbody.fields.description.content[0].content[0].text = (event.issue.hasOwnProperty("vulnerability_description")) ? event.issue.vulnerability_description: event.metadata.recommendation;
		reqbody.fields.customfield_10085 = (event.issue.hasOwnProperty("vulnerability_id")) ? event.issue.vulnerability_id: "";
		reqbody.fields.customfield_10056 = event.issue[selfld.host[event.issueTypeCode]];
		reqbody.fields.customfield_10059 = (event.issue.hasOwnProperty("connection_attributes")) ? event.issue.connection_attributes.dst_ip: "";
		reqbody.fields.customfield_10060 = (event.issue.hasOwnProperty("connection_attributes")) ? event.issue.connection_attributes.dst_port: 0;
		reqbody.fields.customfield_10061 = (event.issue.hasOwnProperty("initial_url")) ? event.issue.initial_url: "";
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
		console.log(JSON.stringify(reqbody));
		request.write(JSON.stringify(reqbody));
		request.end();
	});
};
