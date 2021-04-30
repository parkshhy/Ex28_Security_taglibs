import React, { Component } from 'react';
import { Grid, Cell } from 'react-mdl';

class Landing extends Component {
    render() {
        return (
            <div className="project-grid">
                <Grid className="landing-grid" style={{ height: '50%', marginTop: '5%' }}>
                    <Cell col={12}>
                        <img style={{borderRadius:"30px"}}
                            src="https://ourcodeworld.com/public-media/articles/articleocw-5d07e6b3790af.jpg"
                            alt="avater"
                            className="avatar-img"
                        />
                        <div className="benner-text">
                            <h1>Welcome to MyPage</h1>
                            <hr />
                        </div>
                    </Cell>
                </Grid>
            </div>
        )
    }
}
export default Landing;