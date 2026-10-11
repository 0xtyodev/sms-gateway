import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req:Request)=>{
 const reply=(status:number,body:string)=>new Response(JSON.stringify({message:body}),{status,headers:{"content-type":"application/json"}});
 if(req.method!=="POST")return reply(405,"Method not allowed");
 const secret=Deno.env.get("SMS_WEBHOOK_SECRET"),owner=Deno.env.get("SMS_OWNER_ID");
 if(!secret||!owner)return reply(503,"Not configured");
 const token=req.headers.get("x-webhook-secret")||"";
 const a=new TextEncoder().encode(token),b=new TextEncoder().encode(secret);
 const digest=async(x:Uint8Array)=>new Uint8Array(await crypto.subtle.digest("SHA-256",x));
 const [ha,hb]=await Promise.all([digest(a),digest(b)]);
 let mismatch=0;for(let i=0;i<ha.length;i++)mismatch|=ha[i]^hb[i];
 if(mismatch!==0)return reply(401,"Unauthorized");
 let payload;try{payload=await req.json()}catch{return reply(400,"Invalid JSON")}
 const sender=payload?.sender,message=payload?.message;
 if(typeof sender!=="string"||!sender.trim()||sender.length>160||typeof message!=="string"||!message.trim()||message.length>10000)return reply(400,"Invalid SMS");
 const url=Deno.env.get("SUPABASE_URL"),key=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
 if(!url||!key)return reply(503,"Database unavailable");
 const db=createClient(url,key);
 const {error}=await db.from("sms_messages").insert({owner_id:owner,sender,body:message});
 if(error)return reply(500,"Storage error");
 return reply(201,"Stored");
});