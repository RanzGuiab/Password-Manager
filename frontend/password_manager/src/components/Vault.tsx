const token = localStorage.getItem('vault_token');

const fetchSecrets = async () => {
  try {
    const res = await axios.get('http://localhost:8080/api/v1/vault', {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });
    console.log(res.data);
  } catch (err) {
    console.error("Access Denied", err);
  }
};

