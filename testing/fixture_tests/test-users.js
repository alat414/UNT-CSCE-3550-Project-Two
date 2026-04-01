module.exports=
{
    VALID_USERS: [Nanna, Raggi],

    INVALID_USERS: ['hacker', null, undefined],
    
    TEST_POSTS: 
    [{
        username: 'Nanna',
        title: 'lead singer',

        username: 'Raggi',
        title: 'co-singer',
        
        username: 'Nanna',
        title: 'rhythm guitarist',
        
        username: 'Raggi',
        title: 'lead guitarist',
    }
    ],

    EXPECTED_POSTS:
    {
        'Nanna': 
        [
            {username: 'Nanna', title: 'lead singer'},
            {username: 'Nanna', title: 'rhythm guitarist'},
        ],

        'Raggi':
        [
            {username: 'Raggi', title: 'co-singer'},
            {username: 'Raggi', title: 'lead guitarist'},
        ]
    }
}