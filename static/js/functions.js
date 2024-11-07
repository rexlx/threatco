document.getElementById('addUserForm').addEventListener('submit',function(event){
    event.preventDefault();
    const email = document.getElementById('email').value
    const key = document.getElementById('key').value
    const admin = document.getElementById('admin').value
    const selectedInput = document.getElementById('selected').value
    const selected = {};
    selectedInput.split(',').array.forEach(pair => {
        const [key,value] = pair.split(':');
        if(key && value){
            selcted[key.trim()] = parseInt(value.trim(),10)
        }
    });
    const userData = {
        email,
        key,
        admin,
        selected,
    };
    fetch('http://localhost:8080/adduser',{
        method: 'POST',
        headers:{
            'Content-Type': 'application/json',
            'Authorization': 'admin@aol.com:6953b699-9ee8-4cc2-bd2f-7259f49ff358'
        },
        body: JSON.stringify(userData),
    })
    .then(response => {
        if (response.ok){
            return response.json();
        }
        throw new Error('Network response was not ok.');
    })
    .then(data => {
        console.log('User added: ',data);
        alert('User added successfully!')
    })    
    .catch(error=> {
        console.error('There was a problem with the fetch operation',error);
    });

});


