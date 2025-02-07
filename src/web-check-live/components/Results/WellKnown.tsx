import { Card } from 'web-check-live/components/Form/Card';
import Row, { ListRow }  from 'web-check-live/components/Form/Row';

const styles = `
  grid-row: span 2;
  .content {
    max-height: 50rem;
    overflow-x: hidden;
    overflow-y: auto;
  }
`;

const SecurityTxTCard = (data: any): JSX.Element => {
  const securityTxt = data;
  return (
    <Card styles={cardStyles}>
      <Row lbl="Present" val={securityTxt.isPresent ? '✅ Yes' : '❌ No'} />
      { securityTxt.isPresent && (
        <>
        <Row lbl="File Location" val={securityTxt.foundIn} />
        <Row lbl="PGP Signed" val={securityTxt.isPgpSigned ? '✅ Yes' : '❌ No'} />
        {securityTxt.fields && Object.keys(securityTxt.fields).map((field: string, index: number) => {
          if (securityTxt.fields[field].includes('http')) return (
            <Row lbl="" val="" key={`policy-url-row-${index}`}>
              <span className="lbl">{field}</span>
              <span className="val"><a href={securityTxt.fields[field]}>{getPagePath(securityTxt.fields[field])}</a></span>
            </Row>
          );
          return (
            <Row lbl={field} val={securityTxt.fields[field]} key={`policy-row-${index}`} />
          );
        })}
        <Details>
          <summary>View Full Policy</summary>
          <pre>{securityTxt.content}</pre>
        </Details>
        </>
      )}
      {!securityTxt.isPresent && (<small>
        Having a security.txt ensures security researchers know how and where to safely report vulnerabilities.
      </small>)}
    </Card>
  );
}

// map types to card functions
const wellKnownTypes: { [key: string]: any } = {
  "securityTxt": SecurityTxTCard,
}

// acme-challenge: 
  // amphtml: 
  // api-catalog: 
  // appspecific: 
  // ashrae: 
  // assetlinks.json: 
  // broadband-labels: 
  // brski: 
  // caldav: 
  // carddav: 
  // change-password: 
  // cmp: 
  // coap: 
  // core: 
  // csaf: 
  // csaf-aggregator: 
  // csvm: 
  // did.json: 
  // did-configuration.json: 
  // dnt: 
  // dnt-policy.txt: 
  // dots: 
  // ecips: 
  // edhoc: 
  // enterprise-network-security: 
  // enterprise-transport-security: 
  // est: 
  // genid: 
  // gnap-as-rs: 
  // gpc.json: 
  // gs1resolver: 
  // hoba: 
  // host-meta: 
  // host-meta.json: 
  // hosting-provider: 
  // http-opportunistic: 
  // idp-proxy: 
  // jmap: 
  // keybase.txt: 
  // knx: 
  // looking-glass: 
  // masque: 
  // matrix: 
  // mercure: 
  // mta-sts.txt: 
  // mud: 
  // nfv-oauth-server-configuration: 
  // ni: 
  // nodeinfo: 
  // nostr.json: 
  // oauth-authorization-server: 
  // oauth-protected-resource: 
  // ohttp-gateway: 
  // openid-federation: 
  // open-resource-discovery: 
  // openid-configuration: 
  // openorg: 
  // oslc: 
  // pki-validation: 
  // posh: 
  // privacy-sandbox-attestations.json: 
  // probing.txt: 
  // pvd: 
  // rd: 
  // related-website-set.json: 
  // reload-config: 
  // repute-template: 
  // resourcesync: 
  // sbom:  
  // ssf-configuration: 
  // sshfp: 
  // stun-key: 
  // terraform.json: 
  // thread: 
  // time: 
  // timezone: 
  // tdmrep.json: 
  // tor-relay: 
  // tpcd: 
  // traffic-advice: 
  // trust.txt: 
  // uma2-configuration: 
  // void: 
  // webfinger: 
  // webweaver.json: 
  // wot:






const WellKnownCard = (props: { data: any, title: string, actionButtons: any }): JSX.Element => {
  const wellKnownRecords = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons} styles={styles}>
      <div className="content">
        {Object.keys(wellKnownRecords).map((key: string) => (
          <Row lbl={wellKnownRecords[key].title} val={wellKnownRecords[key].isPresent?'✅ Yes' : '❌ No'} />
          {wellKnownRecords[key].isPresent === true  && (
            <Details>
              <summary>View Full Entry</summary>
              <pre>{wellKnownTypes{key}(wellKnownRecords[key].data)}</pre>
            </Details>
          )
          }
        ))}
      </div>
    </Card>
  );
}

// { wellKnownRecords.A?.length > 0 && <ListRow title="A" list={wellKnownRecords.A} /> }

export default WellKnownCard;
