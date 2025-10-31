
document.getElementById('decryptForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const file = document.getElementById('decryptFile').files[0];
  const password = document.getElementById('decryptPassword').value;

  const formData = new FormData();
  formData.append('file', file);
  formData.append('password', password);

  const response = await fetch('http://127.0.0.1:5000/decrypt', {
    method: 'POST',
    body: formData
  });

  if (response.ok) {
    const blob = await response.blob();
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'decrypted_file.txt';
    link.click();
  } else {
    alert("❌ Decryption failed. Wrong password or corrupted file.");
  }
});
