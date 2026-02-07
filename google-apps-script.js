// ============================================================
// Bu kodu Google Apps Script'e yapistir
// https://script.google.com adresinde yeni proje olustur
// ============================================================

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);
    var to = data.to || '';
    var subject = data.subject || 'Bildirim';
    var html = data.html || '';

    if (!to) {
      return ContentService.createTextOutput(JSON.stringify({ success: false, error: 'to alani bos' }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    // Birden fazla alici varsa virgulle ayrilmis olabilir
    var recipients = to.split(',').map(function(e) { return e.trim(); }).filter(function(e) { return e; });

    for (var i = 0; i < recipients.length; i++) {
      // UTF-8 encoding icin options
      GmailApp.sendEmail(recipients[i], subject, '', {
        htmlBody: html,
        name: 'Ziyaretci Takip'
      });
    }

    return ContentService.createTextOutput(JSON.stringify({ success: true, sent: recipients.length }))
      .setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({ success: false, error: err.message }))
      .setMimeType(ContentService.MimeType.JSON);
  }
}
